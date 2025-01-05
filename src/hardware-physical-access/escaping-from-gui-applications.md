# Échapper des KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Vérifier le dispositif physique

| Composant     | Action                                                              |
| ------------- | ------------------------------------------------------------------- |
| Bouton d'alimentation | Éteindre et rallumer l'appareil peut exposer l'écran de démarrage |
| Câble d'alimentation  | Vérifiez si l'appareil redémarre lorsque l'alimentation est coupée brièvement |
| Ports USB     | Connectez un clavier physique avec plus de raccourcis               |
| Ethernet      | Un scan réseau ou un sniffing peut permettre une exploitation supplémentaire |

## Vérifier les actions possibles dans l'application GUI

**Dialogues communs** sont ces options de **sauvegarde d'un fichier**, **ouverture d'un fichier**, sélection d'une police, d'une couleur... La plupart d'entre eux **offriront une fonctionnalité Explorer complète**. Cela signifie que vous pourrez accéder aux fonctionnalités d'Explorer si vous pouvez accéder à ces options :

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

Peut-être **en utilisant une option `Ouvrir avec`** vous pouvez ouvrir/exécuter une sorte de shell.

#### Windows

Par exemple _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ trouvez plus de binaires qui peuvent être utilisés pour exécuter des commandes (et effectuer des actions inattendues) ici : [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Plus ici : [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Contournement des restrictions de chemin

- **Variables d'environnement** : Il existe de nombreuses variables d'environnement qui pointent vers un certain chemin
- **Autres protocoles** : _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Liens symboliques**
- **Raccourcis** : CTRL+N (ouvrir une nouvelle session), CTRL+R (Exécuter des commandes), CTRL+SHIFT+ESC (Gestionnaire des tâches), Windows+E (ouvrir l'explorateur), CTRL-B, CTRL-I (Favoris), CTRL-H (Historique), CTRL-L, CTRL-O (Dialogue Fichier/Ouvrir), CTRL-P (Dialogue Imprimer), CTRL-S (Enregistrer sous)
- Menu Administratif caché : CTRL-ALT-F8, CTRL-ESC-F9
- **URI Shell** : _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **Chemins UNC** : Chemins pour se connecter à des dossiers partagés. Vous devriez essayer de vous connecter au C$ de la machine locale ("\\\127.0.0.1\c$\Windows\System32")
- **Plus de chemins UNC :**

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

### Téléchargez vos binaires

Console : [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer : [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Éditeur de registre : [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Accéder au système de fichiers depuis le navigateur

| CHEMIN               | CHEMIN             | CHEMIN              | CHEMIN               |
| ------------------- | ------------------ | ------------------- | -------------------- |
| File:/C:/windows    | File:/C:/windows/  | File:/C:/windows\\  | File:/C:\windows     |
| File:/C:\windows\\  | File:/C:\windows/  | File://C:/windows   | File://C:/windows/   |
| File://C:/windows\\ | File://C:\windows  | File://C:\windows/  | File://C:\windows\\  |
| C:/windows          | C:/windows/        | C:/windows\\        | C:\windows           |
| C:\windows\\        | C:\windows/        | %WINDIR%            | %TMP%                |
| %TEMP%              | %SYSTEMDRIVE%      | %SYSTEMROOT%        | %APPDATA%            |
| %HOMEDRIVE%         | %HOMESHARE         |                     | <p><br></p>          |

### Raccourcis

- Touches de maintien – Appuyez sur SHIFT 5 fois
- Touches de souris – SHIFT+ALT+NUMLOCK
- Contraste élevé – SHIFT+ALT+PRINTSCN
- Touches de basculement – Maintenez NUMLOCK pendant 5 secondes
- Touches de filtre – Maintenez SHIFT droit pendant 12 secondes
- WINDOWS+F1 – Recherche Windows
- WINDOWS+D – Afficher le bureau
- WINDOWS+E – Lancer l'explorateur Windows
- WINDOWS+R – Exécuter
- WINDOWS+U – Centre d'accessibilité
- WINDOWS+F – Rechercher
- SHIFT+F10 – Menu contextuel
- CTRL+SHIFT+ESC – Gestionnaire des tâches
- CTRL+ALT+DEL – Écran de démarrage sur les versions Windows plus récentes
- F1 – Aide F3 – Recherche
- F6 – Barre d'adresse
- F11 – Basculer en plein écran dans Internet Explorer
- CTRL+H – Historique d'Internet Explorer
- CTRL+T – Internet Explorer – Nouvel onglet
- CTRL+N – Internet Explorer – Nouvelle page
- CTRL+O – Ouvrir un fichier
- CTRL+S – Enregistrer CTRL+N – Nouveau RDP / Citrix

### Glissements

- Glissez de la gauche vers la droite pour voir toutes les fenêtres ouvertes, minimisant l'application KIOSK et accédant directement à l'ensemble du système d'exploitation ;
- Glissez de la droite vers la gauche pour ouvrir le Centre d'Action, minimisant l'application KIOSK et accédant directement à l'ensemble du système d'exploitation ;
- Glissez depuis le bord supérieur pour rendre la barre de titre visible pour une application ouverte en mode plein écran ;
- Glissez vers le haut depuis le bas pour afficher la barre des tâches dans une application en plein écran.

### Astuces Internet Explorer

#### 'Barre d'outils d'image'

C'est une barre d'outils qui apparaît en haut à gauche de l'image lorsqu'elle est cliquée. Vous pourrez Enregistrer, Imprimer, Mailto, Ouvrir "Mes images" dans l'explorateur. Le Kiosk doit utiliser Internet Explorer.

#### Protocole Shell

Tapez ces URL pour obtenir une vue Explorer :

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
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Mes lieux réseau
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Afficher les extensions de fichier

Consultez cette page pour plus d'informations : [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Astuces pour les navigateurs

Versions de sauvegarde d'iKat :

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Créez un dialogue commun en utilisant JavaScript et accédez à l'explorateur de fichiers : `document.write('<input/type=file>')`\
Source : https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestes et boutons

- Glissez vers le haut avec quatre (ou cinq) doigts / Double-tapez sur le bouton Accueil : Pour voir la vue multitâche et changer d'application
- Glissez d'un côté ou de l'autre avec quatre ou cinq doigts : Pour changer vers l'application suivante/dernière
- Pincez l'écran avec cinq doigts / Touchez le bouton Accueil / Glissez vers le haut avec 1 doigt depuis le bas de l'écran en un mouvement rapide vers le haut : Pour accéder à l'accueil
- Glissez un doigt depuis le bas de l'écran juste 1-2 pouces (lentement) : Le dock apparaîtra
- Glissez vers le bas depuis le haut de l'affichage avec 1 doigt : Pour voir vos notifications
- Glissez vers le bas avec 1 doigt dans le coin supérieur droit de l'écran : Pour voir le centre de contrôle de l'iPad Pro
- Glissez 1 doigt depuis la gauche de l'écran 1-2 pouces : Pour voir la vue Aujourd'hui
- Glissez rapidement 1 doigt depuis le centre de l'écran vers la droite ou la gauche : Pour changer vers l'application suivante/dernière
- Appuyez et maintenez le bouton On/**Off**/Veille dans le coin supérieur droit de l'**iPad +** Déplacez le curseur de mise hors tension complètement vers la droite : Pour éteindre
- Appuyez sur le bouton On/**Off**/Veille dans le coin supérieur droit de l'**iPad et le bouton Accueil pendant quelques secondes** : Pour forcer un arrêt complet
- Appuyez rapidement sur le bouton On/**Off**/Veille dans le coin supérieur droit de l'**iPad et le bouton Accueil** : Pour prendre une capture d'écran qui apparaîtra en bas à gauche de l'affichage. Appuyez sur les deux boutons en même temps très brièvement, car si vous les maintenez quelques secondes, un arrêt complet sera effectué.

### Raccourcis

Vous devriez avoir un clavier iPad ou un adaptateur de clavier USB. Seuls les raccourcis qui pourraient aider à échapper à l'application seront affichés ici.

| Touche | Nom          |
| ------ | ------------ |
| ⌘      | Commande     |
| ⌥      | Option (Alt) |
| ⇧      | Maj         |
| ↩      | Retour       |
| ⇥      | Tab          |
| ^      | Contrôle     |
| ←      | Flèche gauche |
| →      | Flèche droite |
| ↑      | Flèche haut  |
| ↓      | Flèche bas   |

#### Raccourcis système

Ces raccourcis sont pour les paramètres visuels et sonores, selon l'utilisation de l'iPad.

| Raccourci | Action                                                                         |
| --------- | ------------------------------------------------------------------------------ |
| F1        | Diminuer l'écran                                                               |
| F2        | Augmenter l'écran                                                              |
| F7        | Reculer d'une chanson                                                          |
| F8        | Lecture/pause                                                                  |
| F9        | Passer à la chanson suivante                                                    |
| F10       | Couper le son                                                                  |
| F11       | Diminuer le volume                                                             |
| F12       | Augmenter le volume                                                            |
| ⌘ Espace  | Afficher une liste de langues disponibles ; pour en choisir une, appuyez à nouveau sur la barre d'espace. |

#### Navigation sur iPad

| Raccourci                                           | Action                                                  |
| --------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Aller à l'accueil                                       |
| ⌘⇧H (Commande-Shift-H)                              | Aller à l'accueil                                       |
| ⌘ (Espace)                                         | Ouvrir Spotlight                                       |
| ⌘⇥ (Commande-Tab)                                   | Lister les dix dernières applications utilisées         |
| ⌘\~                                                | Aller à la dernière application                         |
| ⌘⇧3 (Commande-Shift-3)                              | Capture d'écran (flotte en bas à gauche pour enregistrer ou agir dessus) |
| ⌘⇧4                                                | Capture d'écran et l'ouvrir dans l'éditeur             |
| Appuyez et maintenez ⌘                              | Liste des raccourcis disponibles pour l'application     |
| ⌘⌥D (Commande-Option/Alt-D)                         | Affiche le dock                                         |
| ^⌥H (Contrôle-Option-H)                             | Bouton d'accueil                                        |
| ^⌥H H (Contrôle-Option-H-H)                         | Afficher la barre multitâche                           |
| ^⌥I (Contrôle-Option-i)                             | Choix d'éléments                                       |
| Échap                                              | Bouton retour                                           |
| → (Flèche droite)                                   | Élément suivant                                         |
| ← (Flèche gauche)                                   | Élément précédent                                       |
| ↑↓ (Flèche haut, Flèche bas)                        | Appuyez simultanément sur l'élément sélectionné        |
| ⌥ ↓ (Option-Flèche bas)                             | Faire défiler vers le bas                               |
| ⌥↑ (Option-Flèche haut)                            | Faire défiler vers le haut                              |
| ⌥← ou ⌥→ (Option-Flèche gauche ou Option-Flèche droite) | Faire défiler à gauche ou à droite                     |
| ^⌥S (Contrôle-Option-S)                             | Activer ou désactiver la synthèse vocale              |
| ⌘⇧⇥ (Commande-Shift-Tab)                            | Passer à l'application précédente                       |
| ⌘⇥ (Commande-Tab)                                   | Revenir à l'application d'origine                       |
| ←+→, puis Option + ← ou Option+→                   | Naviguer à travers le Dock                              |

#### Raccourcis Safari

| Raccourci                | Action                                           |
| ------------------------ | ------------------------------------------------ |
| ⌘L (Commande-L)          | Ouvrir l'emplacement                             |
| ⌘T                      | Ouvrir un nouvel onglet                          |
| ⌘W                      | Fermer l'onglet actuel                           |
| ⌘R                      | Actualiser l'onglet actuel                       |
| ⌘.                      | Arrêter de charger l'onglet actuel              |
| ^⇥                      | Passer à l'onglet suivant                        |
| ^⇧⇥ (Contrôle-Shift-Tab) | Passer à l'onglet précédent                      |
| ⌘L                      | Sélectionner le champ de saisie de texte/URL pour le modifier |
| ⌘⇧T (Commande-Shift-T)   | Ouvrir le dernier onglet fermé (peut être utilisé plusieurs fois) |
| ⌘\[                     | Reculer d'une page dans votre historique de navigation |
| ⌘]                      | Avancer d'une page dans votre historique de navigation |
| ⌘⇧R                     | Activer le mode lecteur                          |

#### Raccourcis Mail

| Raccourci                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Ouvrir l'emplacement         |
| ⌘T                         | Ouvrir un nouvel onglet       |
| ⌘W                         | Fermer l'onglet actuel       |
| ⌘R                         | Actualiser l'onglet actuel   |
| ⌘.                         | Arrêter de charger l'onglet  |
| ⌘⌥F (Commande-Option/Alt-F) | Rechercher dans votre boîte aux lettres |

## Références

- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
