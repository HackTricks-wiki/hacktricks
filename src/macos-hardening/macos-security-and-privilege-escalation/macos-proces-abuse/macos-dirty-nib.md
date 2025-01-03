# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

**Pour plus de détails sur la technique, consultez le post original de :** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) et le post suivant par [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Voici un résumé :

### Qu'est-ce que les fichiers Nib

Les fichiers Nib (abréviation de NeXT Interface Builder), faisant partie de l'écosystème de développement d'Apple, sont destinés à définir **les éléments UI** et leurs interactions dans les applications. Ils englobent des objets sérialisés tels que des fenêtres et des boutons, et sont chargés à l'exécution. Malgré leur utilisation continue, Apple préconise désormais les Storyboards pour une visualisation plus complète du flux UI.

Le fichier Nib principal est référencé dans la valeur **`NSMainNibFile`** à l'intérieur du fichier `Info.plist` de l'application et est chargé par la fonction **`NSApplicationMain`** exécutée dans la fonction `main` de l'application.

### Processus d'injection de Dirty Nib

#### Création et configuration d'un fichier NIB

1. **Configuration initiale** :
- Créez un nouveau fichier NIB à l'aide de XCode.
- Ajoutez un objet à l'interface, en définissant sa classe sur `NSAppleScript`.
- Configurez la propriété `source` initiale via les attributs d'exécution définis par l'utilisateur.
2. **Gadget d'exécution de code** :
- La configuration facilite l'exécution d'AppleScript à la demande.
- Intégrez un bouton pour activer l'objet `Apple Script`, déclenchant spécifiquement le sélecteur `executeAndReturnError:`.
3. **Test** :

- Un simple Apple Script à des fins de test :

```bash
set theDialogText to "PWND"
display dialog theDialogText
```

- Testez en exécutant dans le débogueur XCode et en cliquant sur le bouton.

#### Ciblage d'une application (Exemple : Pages)

1. **Préparation** :
- Copiez l'application cible (par exemple, Pages) dans un répertoire séparé (par exemple, `/tmp/`).
- Lancez l'application pour contourner les problèmes de Gatekeeper et la mettre en cache.
2. **Écrasement du fichier NIB** :
- Remplacez un fichier NIB existant (par exemple, le NIB du panneau À propos) par le fichier DirtyNIB créé.
3. **Exécution** :
- Déclenchez l'exécution en interagissant avec l'application (par exemple, en sélectionnant l'élément de menu `À propos`).

#### Preuve de concept : Accès aux données utilisateur

- Modifiez l'AppleScript pour accéder et extraire des données utilisateur, telles que des photos, sans le consentement de l'utilisateur.

### Exemple de code : Fichier .xib malveillant

- Accédez et examinez un [**exemple de fichier .xib malveillant**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) qui démontre l'exécution de code arbitraire.

### Autre exemple

Dans le post [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) vous pouvez trouver un tutoriel sur la façon de créer un dirty nib.&#x20;

### Aborder les contraintes de lancement

- Les contraintes de lancement entravent l'exécution des applications depuis des emplacements inattendus (par exemple, `/tmp`).
- Il est possible d'identifier les applications non protégées par des contraintes de lancement et de les cibler pour l'injection de fichiers NIB.

### Protections supplémentaires de macOS

Depuis macOS Sonoma, les modifications à l'intérieur des bundles d'applications sont restreintes. Cependant, les méthodes antérieures impliquaient :

1. Copier l'application dans un autre emplacement (par exemple, `/tmp/`).
2. Renommer les répertoires au sein du bundle de l'application pour contourner les protections initiales.
3. Après avoir exécuté l'application pour s'enregistrer auprès de Gatekeeper, modifier le bundle de l'application (par exemple, remplacer MainMenu.nib par Dirty.nib).
4. Renommer les répertoires et relancer l'application pour exécuter le fichier NIB injecté.

**Remarque** : Les mises à jour récentes de macOS ont atténué cette exploitation en empêchant les modifications de fichiers au sein des bundles d'applications après la mise en cache de Gatekeeper, rendant l'exploitation inefficace.

{{#include ../../../banners/hacktricks-training.md}}
