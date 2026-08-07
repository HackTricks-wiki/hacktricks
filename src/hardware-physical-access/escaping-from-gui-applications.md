# Échapper aux KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Vérifier l'appareil physique

| Composant        | Action                                                               |
| ---------------- | -------------------------------------------------------------------- |
| Bouton d'alimentation | Éteindre puis rallumer l'appareil peut afficher l'écran de démarrage |
| Câble d'alimentation | Vérifier si l'appareil redémarre lorsque l'alimentation est brièvement coupée |
| Ports USB        | Connecter un clavier physique avec davantage de raccourcis            |
| Ethernet         | Un scan réseau ou du sniffing peut permettre une exploitation supplémentaire |

## Vérifier les actions possibles dans l'application GUI

Les **boîtes de dialogue courantes** sont les options permettant **d'enregistrer un fichier**, **d'ouvrir un fichier**, de sélectionner une police, une couleur... La plupart d'entre elles **offriront toutes les fonctionnalités d'Explorer**. Cela signifie que vous pourrez accéder aux fonctionnalités d'Explorer si vous pouvez accéder à ces options :

- Fermer/Fermer sous
- Ouvrir/Ouvrir avec
- Imprimer
- Exporter/Importer
- Rechercher
- Scanner

Vous devriez vérifier si vous pouvez :

- Modifier ou créer de nouveaux fichiers
- Créer des liens symboliques
- Accéder à des zones restreintes
- Exécuter d'autres applications

### Exécution de commandes

Peut-être qu'en **utilisant l'option `Open with`**\*\* vous pouvez ouvrir/exécuter une sorte de shell.

#### Windows

Par exemple _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ trouvez ici d'autres binaires pouvant être utilisés pour exécuter des commandes (et effectuer des actions inattendues) : [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Plus d'informations ici : [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Contourner les restrictions de chemin

- **Variables d'environnement** : de nombreuses variables d'environnement pointent vers un chemin
- **Autres protocoles** : _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Liens symboliques**
- **Raccourcis** : CTRL+N (ouvrir une nouvelle session), CTRL+R (exécuter des commandes), CTRL+SHIFT+ESC (Task Manager), Windows+E (ouvrir Explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (boîte de dialogue File/Open), CTRL-P (boîte de dialogue Print), CTRL-S (Save As)
- Menu administratif caché : CTRL-ALT-F8, CTRL-ESC-F9
- **URI Shell** : _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **Chemins UNC** : chemins permettant de se connecter à des dossiers partagés. Vous devriez essayer de vous connecter au lecteur C$ de la machine locale ("\\\127.0.0.1\c$\Windows\System32")
- **Autres chemins UNC :**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%              | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Évasions du bureau restreint (Citrix/RDS/VDI)

- **Pivot via les boîtes de dialogue** : utilisez les boîtes de dialogue *Open/Save/Print-to-file* comme une version allégée d'Explorer. Essayez `*.*` / `*.exe` dans le champ du nom de fichier, cliquez avec le bouton droit sur les dossiers pour utiliser **Open in new window**, et utilisez **Properties → Open file location** pour étendre la navigation.<sup>[[1]](#references)</sup>
- **Créer des chemins d'exécution depuis les boîtes de dialogue** : créez un nouveau fichier et renommez-le en `.CMD` ou `.BAT`, ou créez un raccourci pointant vers `%WINDIR%\System32` (ou vers un binaire spécifique comme `%WINDIR%\System32\cmd.exe`).
- **Pivots de lancement de shell** : si vous pouvez accéder à `cmd.exe`, essayez de faire glisser-déposer n'importe quel fichier dessus pour lancer une invite de commandes. Si Task Manager est accessible (`CTRL+SHIFT+ESC`), utilisez **Run new task**.
- **Contournement de Task Scheduler** : si les shells interactifs sont bloqués mais que la planification est autorisée, créez une tâche pour exécuter `cmd.exe` (avec l'interface GUI `taskschd.msc` ou `schtasks.exe`).
- **Listes d'autorisation faibles** : si l'exécution est autorisée par **nom de fichier/extension**, renommez votre payload avec un nom autorisé. Si elle est autorisée par **répertoire**, copiez le payload dans un dossier de programmes autorisé et exécutez-le depuis cet emplacement.
- **Trouver des chemins de staging accessibles en écriture** : commencez par `%TEMP%` et énumérez les dossiers accessibles en écriture avec Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Étape suivante** : Si vous obtenez un shell, passez à la checklist Windows LPE :
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Télécharger vos binaires

Console : [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer : [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Éditeur de registre : [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

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

- Touches rémanentes – Appuyer 5 fois sur SHIFT
- Touches souris – SHIFT+ALT+NUMLOCK
- Contraste élevé – SHIFT+ALT+PRINTSCN
- Touches bascules – Maintenir NUMLOCK pendant 5 secondes
- Touches filtres – Maintenir SHIFT droit pendant 12 secondes
- WINDOWS+F1 – Recherche Windows
- WINDOWS+D – Afficher le bureau
- WINDOWS+E – Lancer Windows Explorer
- WINDOWS+R – Exécuter
- WINDOWS+U – Options d’ergonomie
- WINDOWS+F – Rechercher
- SHIFT+F10 – Menu contextuel
- CTRL+SHIFT+ESC – Gestionnaire des tâches
- CTRL+ALT+DEL – Écran de démarrage sur les versions récentes de Windows
- F1 – Aide F3 – Rechercher
- F6 – Barre d’adresse
- F11 – Activer/désactiver le plein écran dans Internet Explorer
- CTRL+H – Historique d’Internet Explorer
- CTRL+T – Internet Explorer – Nouvel onglet
- CTRL+N – Internet Explorer – Nouvelle page
- CTRL+O – Ouvrir un fichier
- CTRL+S – Enregistrer CTRL+N – Nouvelle connexion RDP / Citrix

### Gestes

- Balayer de la gauche vers la droite pour voir toutes les fenêtres Windows ouvertes, réduire l’application KIOSK et accéder directement à l’ensemble du système d’exploitation ;
- Balayer de la droite vers la gauche pour ouvrir le Centre de notifications, réduire l’application KIOSK et accéder directement à l’ensemble du système d’exploitation ;
- Balayer depuis le bord supérieur pour rendre visible la barre de titre d’une application ouverte en mode plein écran ;
- Balayer vers le haut depuis le bas pour afficher la barre des tâches dans une application en plein écran.

### Astuces Internet Explorer

#### 'Image Toolbar'

Il s’agit d’une barre d’outils qui apparaît en haut à gauche d’une image lorsque celle-ci est sélectionnée. Vous pourrez enregistrer, imprimer, envoyer par e-mail et ouvrir « Mes images » dans Explorer. Le Kiosk doit utiliser Internet Explorer.

#### Shell Protocol

Saisissez ces URLs pour obtenir une vue Explorer :

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
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Poste de travail
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Favoris réseau
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Afficher les extensions de fichiers

Consultez cette page pour plus d’informations : [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Astuces des navigateurs

Versions de sauvegarde d’iKat :

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Créer une boîte de dialogue commune avec JavaScript et accéder à l’explorateur de fichiers : `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestes et boutons

- Balayer vers le haut avec quatre (ou cinq) doigts / Appuyer deux fois sur le bouton Home : afficher la vue multitâche et changer d’application
- Balayer dans un sens ou dans l’autre avec quatre ou cinq doigts : passer à l’application suivante/précédente
- Pincer l’écran avec cinq doigts / Appuyer sur le bouton Home / Balayer rapidement vers le haut avec 1 doigt depuis le bas de l’écran : accéder à l’écran d’accueil
- Balayer avec un doigt depuis le bas de l’écran sur seulement 1 à 2 pouces (lentement) : le dock apparaît
- Balayer vers le bas depuis le haut de l’écran avec 1 doigt : afficher vos notifications
- Balayer vers le bas avec 1 doigt depuis le coin supérieur droit de l’écran : afficher le centre de contrôle de l’iPad Pro
- Balayer avec 1 doigt depuis le bord gauche de l’écran sur 1 à 2 pouces : afficher la vue Aujourd’hui
- Balayer rapidement avec 1 doigt depuis le centre de l’écran vers la droite ou la gauche : passer à l’application suivante/précédente
- Maintenir le bouton Marche/**Arrêt**/Veille situé dans le coin supérieur droit de l’**iPad +** déplacer complètement le curseur **éteindre** vers la droite : éteindre l’appareil
- Appuyer sur le bouton Marche/**Arrêt**/Veille situé dans le coin supérieur droit de l’**iPad et sur le bouton Home pendant quelques secondes** : forcer l’arrêt complet
- Appuyer rapidement sur le bouton Marche/**Arrêt**/Veille situé dans le coin supérieur droit de l’**iPad et sur le bouton Home** : prendre une capture d’écran qui apparaîtra dans le coin inférieur gauche de l’écran. Appuyez très brièvement sur les deux boutons en même temps ; si vous les maintenez pendant quelques secondes, un arrêt complet sera effectué.<sup>[[3]](#references)</sup>

### Raccourcis

Vous devez disposer d’un clavier iPad ou d’un adaptateur de clavier USB. Seuls les raccourcis pouvant aider à sortir de l’application sont présentés ici.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

| Touche | Nom          |
| ------ | ------------ |
| ⌘      | Command      |
| ⌥      | Option (Alt) |
| ⇧      | Shift        |
| ↩      | Return       |
| ⇥      | Tab          |
| ^      | Control      |
| ←      | Flèche gauche |
| →      | Flèche droite |
| ↑      | Flèche haut  |
| ↓      | Flèche bas   |

#### Raccourcis système

Ces raccourcis concernent les réglages d’affichage et du son, selon l’utilisation de l’iPad.

| Raccourci | Action                                                                         |
| --------- | ----------------------------------------------------------------------------- |
| F1        | Réduire la luminosité de l’écran                                              |
| F2        | Augmenter la luminosité de l’écran                                             |
| F7        | Chanson précédente                                                             |
| F8        | Lecture/pause                                                                  |
| F9        | Chanson suivante                                                               |
| F10       | Couper le son                                                                  |
| F11       | Réduire le volume                                                              |
| F12       | Augmenter le volume                                                           |
| ⌘ Space   | Afficher la liste des langues disponibles ; pour en choisir une, appuyer à nouveau sur la barre d’espace. |

#### Navigation sur iPad

| Raccourci                                           | Action                                                  |
| --------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                  | Aller à l’écran d’accueil                               |
| ⌘⇧H (Command-Shift-H)                               | Aller à l’écran d’accueil                               |
| ⌘ (Space)                                           | Ouvrir Spotlight                                        |
| ⌘⇥ (Command-Tab)                                    | Afficher les dix dernières applications utilisées       |
| ⌘\~                                                 | Aller à la dernière application                          |
| ⌘⇧3 (Command-Shift-3)                               | Capture d’écran (apparaît en bas à gauche pour être enregistrée ou traitée) |
| ⌘⇧4                                                 | Prendre une capture d’écran et l’ouvrir dans l’éditeur |
| Maintenir ⌘                                          | Afficher la liste des raccourcis disponibles pour l’application |
| ⌘⌥D (Command-Option/Alt-D)                          | Afficher le dock                                        |
| ^⌥H (Control-Option-H)                              | Bouton Home                                             |
| ^⌥H H (Control-Option-H-H)                           | Afficher la barre multitâche                            |
| ^⌥I (Control-Option-i)                              | Sélecteur d’élément                                     |
| Escape                                              | Bouton Retour                                           |
| → (Right arrow)                                     | Élément suivant                                         |
| ← (Left arrow)                                      | Élément précédent                                       |
| ↑↓ (Up arrow, Down arrow)                           | Appuyer simultanément sur l’élément sélectionné        |
| ⌥ ↓ (Option-Down arrow)                             | Faire défiler vers le bas                               |
| ⌥↑ (Option-Up arrow)                                | Faire défiler vers le haut                              |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow)  | Faire défiler vers la gauche ou la droite               |
| ^⌥S (Control-Option-S)                              | Activer ou désactiver la synthèse vocale VoiceOver      |
| ⌘⇧⇥ (Command-Shift-Tab)                             | Passer à l’application précédente                        |
| ⌘⇥ (Command-Tab)                                    | Revenir à l’application d’origine                       |
| ←+→, then Option + ← or Option+→                    | Naviguer dans le Dock                                   |

#### Raccourcis Safari

| Raccourci                | Action                                           |
| ------------------------ | ------------------------------------------------ |
| ⌘L (Command-L)           | Ouvrir l’emplacement                              |
| ⌘T                      | Ouvrir un nouvel onglet                            |
| ⌘W                      | Fermer l’onglet actuel                             |
| ⌘R                      | Actualiser l’onglet actuel                         |
| ⌘.                      | Arrêter le chargement de l’onglet actuel           |
| ^⇥                      | Passer à l’onglet suivant                          |
| ^⇧⇥ (Control-Shift-Tab) | Passer à l’onglet précédent                         |
| ⌘L                      | Sélectionner le champ de saisie/URL pour le modifier |
| ⌘⇧T (Command-Shift-T)   | Ouvrir le dernier onglet fermé (peut être utilisé plusieurs fois) |
| ⌘\[                     | Revenir en arrière d’une page dans l’historique de navigation |
| ⌘]                      | Avancer d’une page dans l’historique de navigation |
| ⌘⇧R                     | Activer le mode Lecteur                             |

#### Raccourcis Mail

| Raccourci                   | Action                       |
| --------------------------- | ---------------------------- |
| ⌘L                         | Ouvrir l’emplacement          |
| ⌘T                         | Ouvrir un nouvel onglet       |
| ⌘W                         | Fermer l’onglet actuel        |
| ⌘R                         | Actualiser l’onglet actuel    |
| ⌘.                         | Arrêter le chargement de l’onglet actuel |
| ⌘⌥F (Command-Option/Alt-F) | Rechercher dans votre boîte aux lettres |

## Références

- [1] [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Give me a browser, I'll give you a shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 only-for-iPad gestures you need to know](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Best iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Show File Extensions In Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
