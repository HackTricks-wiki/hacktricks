# Évasion depuis les KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Vérifier l'appareil physique

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Éteindre puis rallumer l'appareil peut afficher l'écran de démarrage |
| Power cable  | Vérifier si l'appareil redémarre lorsque l'alimentation est coupée brièvement |
| USB ports    | Connecter un clavier physique pour plus de raccourcis              |
| Ethernet     | Un scan ou sniffing réseau peut permettre d'autres exploitations   |

## Vérifier les actions possibles dans l'application GUI

**Common Dialogs** sont ces options de **sauvegarde d'un fichier**, **ouverture d'un fichier**, sélection d'une police, d'une couleur... La plupart offriront une **fonctionnalité complète d'Explorer**. Cela signifie que vous pourrez accéder aux fonctionnalités d'Explorer si vous pouvez atteindre ces options:

- Fermer/Fermer sous
- Ouvrir/Ouvrir avec
- Imprimer
- Exporter/Importer
- Rechercher
- Scanner

Vous devriez vérifier si vous pouvez:

- Modifier ou créer de nouveaux fichiers
- Créer des liens symboliques
- Accéder à des zones restreintes
- Exécuter d'autres applications

### Exécution de commandes

Peut-être **en utilisant `Open with`** option\*\* vous pouvez ouvrir/exécuter une sorte de shell.

#### Windows

Par exemple _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ trouvez plus de binaires pouvant être utilisés pour exécuter des commandes (et effectuer des actions inattendues) ici: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Plus d'infos ici: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Contourner les restrictions de chemin

- **Variables d'environnement**: Il existe de nombreuses variables d'environnement pointant vers des chemins
- **Autres protocoles**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Liens symboliques**
- **Raccourcis clavier**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Menu Administratif caché: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Chemins pour se connecter à des dossiers partagés. Essayez de vous connecter au C$ de la machine locale ("\\\127.0.0.1\c$\Windows\System32")
- **Plus de chemins UNC:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Évasions du bureau restreint (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Use *Open/Save/Print-to-file* dialogs as Explorer-lite. Try `*.*` / `*.exe` in the filename field, right-click folders for **Open in new window**, and use **Properties → Open file location** to expand navigation.
- **Create execution paths from dialogs**: Créez un nouveau fichier et renommez-le en `.CMD` ou `.BAT`, ou créez un raccourci pointant vers `%WINDIR%\System32` (ou un binaire spécifique comme `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Si vous pouvez naviguer jusqu'à `cmd.exe`, essayez de **drag-and-drop** n'importe quel fichier dessus pour lancer un prompt. Si le Task Manager est accessible (`CTRL+SHIFT+ESC`), utilisez **Run new task**.
- **Task Scheduler bypass**: Si les shells interactifs sont bloqués mais que la planification est autorisée, créez une tâche pour exécuter `cmd.exe` (GUI `taskschd.msc` ou `schtasks.exe`).
- **Weak allowlists**: Si l'exécution est autorisée par **filename/extension**, renommez votre payload avec un nom permis. Si l'autorisation se fait par **directory**, copiez le payload dans un dossier de programme autorisé et exécutez-le depuis là.
- **Find writable staging paths**: Commencez par `%TEMP%` et énumérez les dossiers accessibles en écriture avec Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Étape suivante** : Si vous obtenez un shell, pivotez vers la checklist Windows LPE :
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Télécharger vos binaires

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Éditeur de registre: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Accéder au système de fichiers depuis le navigateur

| CHEMIN              | CHEMIN            | CHEMIN             | CHEMIN              |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Raccourcis

- Sticky Keys – Appuyez sur SHIFT 5 fois
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Maintenir NUMLOCK pendant 5 secondes
- Filter Keys – Maintenir la touche SHIFT droite pendant 12 secondes
- WINDOWS+F1 – Recherche Windows
- WINDOWS+D – Afficher le Bureau
- WINDOWS+E – Lancer Windows Explorer
- WINDOWS+R – Exécuter
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Rechercher
- SHIFT+F10 – Menu contextuel
- CTRL+SHIFT+ESC – Gestionnaire des tâches
- CTRL+ALT+DEL – Écran d'accueil sur les versions récentes de Windows
- F1 – Aide F3 – Rechercher
- F6 – Barre d'adresse
- F11 – Basculer en plein écran dans Internet Explorer
- CTRL+H – Historique d'Internet Explorer
- CTRL+T – Internet Explorer – Nouvel onglet
- CTRL+N – Internet Explorer – Nouvelle page
- CTRL+O – Ouvrir un fichier
- CTRL+S – Enregistrer CTRL+N – Nouveau RDP / Citrix

### Glissements

- Glisser depuis le bord gauche vers la droite pour voir toutes les fenêtres ouvertes, minimisant l'application KIOSK et accédant directement à tout le système ;
- Glisser depuis le bord droit vers la gauche pour ouvrir l'Action Center, minimisant l'application KIOSK et accédant directement à tout le système ;
- Glisser depuis le bord supérieur vers l'intérieur pour rendre la barre de titre visible pour une application ouverte en mode plein écran ;
- Glisser vers le haut depuis le bas pour afficher la barre des tâches dans une application en plein écran.

### Astuces Internet Explorer

#### 'Image Toolbar'

C'est une barre d'outils qui apparaît en haut à gauche d'une image lorsqu'on clique dessus. Vous pourrez Sauvegarder, Imprimer, Mailto, Ouvrir "My Pictures" dans Explorer. Le Kiosk doit utiliser Internet Explorer.

#### Shell Protocol

Tapez ces URLs pour obtenir une vue Explorer :

- `shell:Administrative Tools`
- `shell:DocumentsLibrary`
- `shell:Libraries`
- `shell:UserProfiles`
- `shell:Personal`
- `shell:SearchHomeFolder`
- `shell:NetworkPlacesFolder`
- `shell:SendTo`
- `shell:UserProfiles`
- `shell:Common Administrative Tools`
- `shell:MyComputerFolder`
- `shell:InternetFolder`
- `Shell:Profile`
- `Shell:ProgramFiles`
- `Shell:System`
- `Shell:ControlPanelFolder`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Panneau de configuration
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Mon ordinateur
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Mes emplacements réseau
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Afficher les extensions de fichiers

Consultez cette page pour plus d'informations : [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Astuces pour navigateurs

Versions de secours iKat :

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Créez une boîte de dialogue commune en utilisant JavaScript et accédez à l'explorateur de fichiers : `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestes et boutons

- Glissez vers le haut avec quatre (ou cinq) doigts / Double-tapez le bouton Home : Pour afficher la vue multitâche et changer d'app
- Glissez d'un côté ou de l'autre avec quatre ou cinq doigts : Pour passer à l'app suivante/précédente
- Pincez l'écran avec cinq doigts / Touchez le bouton Home / Glissez vers le haut avec 1 doigt depuis le bas de l'écran d'un mouvement rapide vers le haut : Pour accéder à l'écran d'accueil
- Glissez un doigt depuis le bas de l'écran sur 1-2 pouces (lentement) : Le dock apparaîtra
- Glissez vers le bas depuis le haut de l'écran avec 1 doigt : Pour afficher vos notifications
- Glissez vers le bas avec 1 doigt le coin supérieur droit de l'écran : Pour voir le centre de contrôle de l'iPad Pro
- Glissez 1 doigt depuis la gauche de l'écran sur 1-2 pouces : Pour voir la vue Aujourd'hui
- Glissez rapidement 1 doigt depuis le centre de l'écran vers la droite ou la gauche : Pour changer d'app suivante/précédente
- Appuyez et maintenez le bouton On/Off/Sleep en haut à droite de l'iPad + Déplacez le curseur Slide to power off tout à droite : Pour éteindre
- Appuyez sur le bouton On/Off/Sleep en haut à droite de l'iPad et le bouton Home pendant quelques secondes : Pour forcer l'arrêt
- Appuyez rapidement sur le bouton On/Off/Sleep en haut à droite de l'iPad et le bouton Home : Pour prendre une capture d'écran qui apparaîtra en bas à gauche de l'écran. Appuyez très brièvement sur les deux boutons en même temps ; si vous les maintenez quelques secondes un arrêt forcé sera effectué.

### Raccourcis

Vous devriez avoir un clavier iPad ou un adaptateur clavier USB. Seuls les raccourcis susceptibles d'aider à échapper de l'application seront montrés ici.

| Touche | Nom          |
| ------ | ------------ |
| ⌘      | Command      |
| ⌥      | Option (Alt) |
| ⇧      | Shift        |
| ↩      | Return       |
| ⇥      | Tab          |
| ^      | Control      |
| ←      | Flèche gauche|
| →      | Flèche droite|
| ↑      | Flèche haut  |
| ↓      | Flèche bas   |

#### Raccourcis système

Ces raccourcis concernent les réglages visuels et sonores, selon l'usage de l'iPad.

| Raccourci | Action                                              |
| --------- | --------------------------------------------------- |
| F1        | Baisser la luminosité                               |
| F2        | Augmenter la luminosité                             |
| F7        | Morceau précédent                                   |
| F8        | Lecture/pause                                       |
| F9        | Morceau suivant                                     |
| F10       | Muet                                                |
| F11       | Diminuer le volume                                  |
| F12       | Augmenter le volume                                 |
| ⌘ Space   | Affiche une liste de langues disponibles ; pour en choisir une, appuyez de nouveau sur la barre d'espace. |

#### Navigation iPad

| Raccourci                   | Action                                                    |
| -------------------------- | --------------------------------------------------------- |
| ⌘H                         | Aller à l'écran d'accueil                                 |
| ⌘⇧H (Command-Shift-H)       | Aller à l'écran d'accueil                                 |
| ⌘ (Space)                  | Ouvrir Spotlight                                          |
| ⌘⇥ (Command-Tab)           | Lister les dix dernières apps utilisées                   |
| ⌘\~                        | Aller à la dernière app                                   |
| ⌘⇧3 (Command-Shift-3)      | Capture d'écran (s'affiche en bas à gauche pour sauvegarder ou agir dessus) |
| ⌘⇧4                      | Capture d'écran et ouvre l'éditeur                        |
| Appuyez et maintenez ⌘     | Liste des raccourcis disponibles pour l'app               |
| ⌘⌥D (Command-Option/Alt-D) | Affiche le dock                                           |
| ^⌥H (Control-Option-H)     | Bouton Home                                               |
| ^⌥H H (Control-Option-H-H) | Afficher la barre multitâche                              |
| ^⌥I (Control-Option-i)     | Sélecteur d'éléments                                      |
| Escape                     | Bouton Retour                                             |
| → (Flèche droite)          | Élément suivant                                           |
| ← (Flèche gauche)          | Élément précédent                                         |
| ↑↓ (Flèche haut, bas)      | Taper simultanément l'élément sélectionné                |
| ⌥ ↓ (Option-Flèche bas)    | Faire défiler vers le bas                                 |
| ⌥↑ (Option-Flèche haut)    | Faire défiler vers le haut                                |
| ⌥← ou ⌥→                  | Faire défiler à gauche ou à droite                        |
| ^⌥S (Control-Option-S)     | Activer/désactiver la synthèse vocale VoiceOver          |
| ⌘⇧⇥ (Command-Shift-Tab)    | Passer à l'application précédente                         |
| ⌘⇥ (Command-Tab)           | Revenir à l'application d'origine                        |
| ←+→, puis Option + ← ou Option+→ | Naviguer dans le Dock                               |

#### Raccourcis Safari

| Raccourci                | Action                                          |
| ------------------------ | ----------------------------------------------- |
| ⌘L (Command-L)           | Ouvrir la barre d'adresse                       |
| ⌘T                      | Ouvrir un nouvel onglet                         |
| ⌘W                      | Fermer l'onglet courant                         |
| ⌘R                      | Actualiser l'onglet courant                     |
| ⌘.                      | Arrêter le chargement de l'onglet courant       |
| ^⇥                      | Passer à l'onglet suivant                       |
| ^⇧⇥ (Control-Shift-Tab) | Aller à l'onglet précédent                      |
| ⌘L                      | Sélectionner le champ de texte/URL pour le modifier |
| ⌘⇧T (Command-Shift-T)   | Ouvrir le dernier onglet fermé (peut être utilisé plusieurs fois) |
| ⌘\[                     | Reculer d'une page dans l'historique de navigation |
| ⌘]                      | Avancer d'une page dans l'historique de navigation |
| ⌘⇧R                    | Activer le mode Lecteur                          |

#### Raccourcis Mail

| Raccourci                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Ouvrir la localisation       |
| ⌘T                         | Ouvrir un nouvel onglet      |
| ⌘W                         | Fermer l'onglet courant      |
| ⌘R                         | Actualiser l'onglet courant  |
| ⌘.                         | Arrêter le chargement        |
| ⌘⌥F (Command-Option/Alt-F) | Rechercher dans votre mailbox|

## Références

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
