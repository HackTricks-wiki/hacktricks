# Évasion des KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Vérifier l'appareil physique

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Éteindre et rallumer l'appareil peut afficher l'écran de démarrage |
| Power cable  | Vérifiez si l'appareil redémarre quand l'alimentation est coupée brièvement |
| USB ports    | Connectez un clavier physique offrant plus de raccourcis           |
| Ethernet     | Un scan réseau ou sniffing peut permettre une exploitation supplémentaire |

## Vérifier les actions possibles dans l'application GUI

**Boîtes de dialogue courantes** sont les options de **sauvegarde d'un fichier**, **ouverture d'un fichier**, sélection d'une police, d'une couleur... La plupart offriront **une fonctionnalité complète d'Explorer**. Cela signifie que vous pourrez accéder aux fonctionnalités d'Explorer si vous pouvez accéder à ces options :

- Fermer/Fermer en tant que
- Ouvrir/Ouvrir avec
- Imprimer
- Exporter/Importer
- Rechercher
- Scanner

Vous devez vérifier si vous pouvez :

- Modifier ou créer de nouveaux fichiers
- Créer des liens symboliques
- Accéder à des zones restreintes
- Exécuter d'autres applications

### Exécution de commandes

Peut-être qu'en **utilisant l'option `Open with`**\*\* vous pouvez ouvrir/exécuter une sorte de shell.

#### Windows

Par exemple _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ trouvez plus de binaires pouvant être utilisés pour exécuter des commandes (et réaliser des actions inattendues) ici: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Plus d'infos ici: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Contourner les restrictions de chemin

- **Variables d'environnement**: Il existe de nombreuses variables d'environnement qui pointent vers des chemins
- **Autres protocoles**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Liens symboliques**
- **Raccourcis**: CTRL+N (ouvrir une nouvelle session), CTRL+R (Exécuter des commandes), CTRL+SHIFT+ESC (Gestionnaire des tâches), Windows+E (ouvrir l'Explorer), CTRL-B, CTRL-I (Favoris), CTRL-H (Historique), CTRL-L, CTRL-O (Boîte de dialogue Fichier/Ouvrir), CTRL-P (Boîte de dialogue Imprimer), CTRL-S (Enregistrer sous)
- Menu administratif caché: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Chemins pour se connecter à des dossiers partagés. Essayez de vous connecter au C$ de la machine locale ("\\\127.0.0.1\c$\Windows\System32")
- **More UNC paths:**

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

### Restricted Desktop Breakouts (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Use *Open/Save/Print-to-file* dialogs as Explorer-lite. Try `*.*` / `*.exe` in the filename field, right-click folders for **Open in new window**, and use **Properties → Open file location** to expand navigation.
- **Create execution paths from dialogs**: Create a new file and rename it to `.CMD` or `.BAT`, or create a shortcut pointing to `%WINDIR%\System32` (or a specific binary like `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: If you can browse to `cmd.exe`, try **drag-and-drop** any file onto it to launch a prompt. If Task Manager is reachable (`CTRL+SHIFT+ESC`), use **Run new task**.
- **Task Scheduler bypass**: If interactive shells are blocked but scheduling is allowed, create a task to run `cmd.exe` (GUI `taskschd.msc` or `schtasks.exe`).
- **Weak allowlists**: If execution is allowed by **filename/extension**, rename your payload to a permitted name. If allowed by **directory**, copy the payload into an allowed program folder and run it there.
- **Find writable staging paths**: Start with `%TEMP%` and enumerate writeable folders with Sysinternals AccessChk.
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

| PATH                | PATH              | PATH               | PATH                |
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
- Toggle Keys – Maintenez NUMLOCK pendant 5 secondes
- Filter Keys – Maintenez la touche SHIFT droite pendant 12 secondes
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Afficher le Bureau
- WINDOWS+E – Lancer Windows Explorer
- WINDOWS+R – Exécuter
- WINDOWS+U – Centre d’ergonomie (Ease of Access Centre)
- WINDOWS+F – Rechercher
- SHIFT+F10 – Menu contextuel
- CTRL+SHIFT+ESC – Gestionnaire des tâches
- CTRL+ALT+DEL – Écran d’accueil sur les versions récentes de Windows
- F1 – Aide F3 – Recherche
- F6 – Barre d’adresses
- F11 – Basculer en plein écran dans Internet Explorer
- CTRL+H – Historique d’Internet Explorer
- CTRL+T – Internet Explorer – Nouvel onglet
- CTRL+N – Internet Explorer – Nouvelle page
- CTRL+O – Ouvrir un fichier
- CTRL+S – Enregistrer CTRL+N – Nouveau RDP / Citrix

### Gestes

- Balayez du côté gauche vers la droite pour voir toutes les fenêtres ouvertes, minimisant l’application KIOSK et accédant directement à l’ensemble du système ;
- Balayez du côté droit vers la gauche pour ouvrir le Centre d’Action, minimisant l’application KIOSK et accédant directement à l’ensemble du système ;
- Balayez depuis le bord supérieur pour rendre la barre de titre visible pour une application ouverte en plein écran ;
- Balayez vers le haut depuis le bas pour afficher la barre des tâches dans une application en plein écran.

### Astuces Internet Explorer

#### 'Image Toolbar'

C’est une barre d’outils qui apparaît en haut à gauche d’une image lorsqu’on clique dessus. Vous pourrez Enregistrer, Imprimer, Mailto, Ouvrir "My Pictures" dans l’Explorer. Le Kiosk doit utiliser Internet Explorer.

#### Protocole Shell

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
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Afficher les extensions de fichier

Consultez cette page pour plus d’informations : [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Astuces pour navigateurs

Versions de secours iKat :

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Créez une boîte de dialogue commune en JavaScript et accédez à l’explorateur de fichiers : `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestes et boutons

- Balayez vers le haut avec quatre (ou cinq) doigts / Double-cliquez sur le bouton Home : Pour afficher la vue multitâche et changer d’app
- Balayez d’un côté ou de l’autre avec quatre ou cinq doigts : Pour passer à l’app suivante/précédente
- Pincez l’écran avec cinq doigts / Appuyez sur le bouton Home / Balayez vers le haut avec 1 doigt depuis le bas de l’écran en un mouvement rapide vers le haut : Pour accéder à l’écran d’accueil
- Balayez un doigt depuis le bas de l’écran sur 1-2 pouces (lentement) : Le dock apparaîtra
- Balayez vers le bas depuis le haut de l’écran avec 1 doigt : Pour voir vos notifications
- Balayez vers le bas avec 1 doigt depuis le coin supérieur droit de l’écran : Pour voir le centre de contrôle de l’iPad Pro
- Balayez 1 doigt depuis la gauche de l’écran sur 1-2 pouces : Pour voir la vue Aujourd’hui
- Balayez rapidement 1 doigt depuis le centre de l’écran vers la droite ou la gauche : Pour changer d’app suivante/précédente
- Appuyez et maintenez le bouton On/**Off**/Sleep en haut à droite de l’**iPad +** Déplacez le curseur **power off** complètement vers la droite : Pour éteindre
- Appuyez sur le bouton On/**Off**/Sleep en haut à droite de l’**iPad et le bouton Home pendant quelques secondes** : Pour forcer un arrêt complet
- Appuyez sur le bouton On/**Off**/Sleep en haut à droite de l’**iPad et le bouton Home rapidement** : Pour prendre une capture d’écran qui apparaîtra en bas à gauche de l’écran. Appuyez brièvement sur les deux boutons en même temps ; si vous les maintenez quelques secondes un arrêt forcé sera effectué.

### Raccourcis

Vous devriez avoir un clavier iPad ou un adaptateur clavier USB. Seuls les raccourcis pouvant aider à s’échapper de l’application sont affichés ici.

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### Raccourcis système

Ces raccourcis concernent les réglages visuels et sonores, selon l’utilisation de l’iPad.

| Shortcut | Action                                                                 |
| -------- | ---------------------------------------------------------------------- |
| F1       | Diminuer la luminosité                                                 |
| F2       | Augmenter la luminosité                                                |
| F7       | Morceau précédent                                                      |
| F8       | Lecture/pause                                                          |
| F9       | Morceau suivant                                                        |
| F10      | Muet                                                                   |
| F11      | Diminuer le volume                                                     |
| F12      | Augmenter le volume                                                    |
| ⌘ Space  | Afficher la liste des langues disponibles ; pour en choisir une, appuyez de nouveau sur la barre d’espace. |

#### Navigation iPad

| Shortcut                                           | Action                                                                     |
| -------------------------------------------------- | -------------------------------------------------------------------------- |
| ⌘H                                                 | Aller à l’écran d’accueil                                                  |
| ⌘⇧H (Command-Shift-H)                              | Aller à l’écran d’accueil                                                  |
| ⌘ (Space)                                          | Ouvrir Spotlight                                                           |
| ⌘⇥ (Command-Tab)                                   | Lister les dix dernières apps utilisées                                   |
| ⌘\~                                                | Aller à la dernière app                                                    |
| ⌘⇧3 (Command-Shift-3)                              | Capture d’écran (apparaît en bas à gauche pour enregistrer ou agir dessus) |
| ⌘⇧4                                                | Capture d’écran et l’ouvrir dans l’éditeur                                |
| Press and hold ⌘                                   | Liste des raccourcis disponibles pour l’app                               |
| ⌘⌥D (Command-Option/Alt-D)                         | Affiche le dock                                                           |
| ^⌥H (Control-Option-H)                             | Bouton Home                                                                |
| ^⌥H H (Control-Option-H-H)                         | Afficher la barre multitâche                                               |
| ^⌥I (Control-Option-i)                             | Choix d’élément                                                            |
| Escape                                             | Bouton Retour                                                              |
| → (Right arrow)                                    | Élément suivant                                                            |
| ← (Left arrow)                                     | Élément précédent                                                          |
| ↑↓ (Up arrow, Down arrow)                          | Taper simultanément l’élément sélectionné                                 |
| ⌥ ↓ (Option-Down arrow)                            | Faire défiler vers le bas                                                  |
| ⌥↑ (Option-Up arrow)                               | Faire défiler vers le haut                                                 |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Faire défiler à gauche ou à droite                                         |
| ^⌥S (Control-Option-S)                             | Activer/désactiver la parole VoiceOver                                    |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Passer à l’app précédente                                                  |
| ⌘⇥ (Command-Tab)                                   | Revenir à l’app originale                                                  |
| ←+→, then Option + ← or Option+→                   | Naviguer dans le Dock                                                      |

#### Raccourcis Safari

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Ouvrir l’emplacement                              |
| ⌘T                      | Ouvrir un nouvel onglet                          |
| ⌘W                      | Fermer l’onglet courant                          |
| ⌘R                      | Actualiser l’onglet courant                      |
| ⌘.                      | Arrêter le chargement de l’onglet courant        |
| ^⇥                      | Passer à l’onglet suivant                        |
| ^⇧⇥ (Control-Shift-Tab) | Aller à l’onglet précédent                       |
| ⌘L                      | Sélectionner le champ d’URL pour le modifier    |
| ⌘⇧T (Command-Shift-T)   | Ouvrir le dernier onglet fermé (plusieurs fois possible) |
| ⌘\[                     | Revenir d’une page dans l’historique             |
| ⌘]                      | Avancer d’une page dans l’historique             |
| ⌘⇧R                     | Activer le Mode Lecture                           |

#### Raccourcis Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Ouvrir l’emplacement         |
| ⌘T                         | Ouvrir un nouvel onglet      |
| ⌘W                         | Fermer l’onglet courant      |
| ⌘R                         | Actualiser l’onglet courant  |
| ⌘.                         | Arrêter le chargement        |
| ⌘⌥F (Command-Option/Alt-F) | Rechercher dans votre boîte mail |

## Références

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
