# Exécution virtualisée de Payload et évasion par VM personnalisée

{{#include ../banners/hacktricks-training.md}}

La virtualisation de Payload compile la logique offensive en un jeu d’instructions invité, puis l’exécute avec un interpréteur natif. Contrairement à un packer, qui doit finir par exposer les instructions natives d’origine en mémoire, un payload virtualisé peut conserver la logique protégée sous forme de bytecode pendant toute son exécution. Cela supprime cette fenêtre de décompression spécifique, mais **ne** masque **pas** les comportements visibles par l’hôte, tels que les syscalls, l’activité réseau ou la frontière entre la VM et les appels natifs.<sup>[[2]](#references)[[3]](#references)</sup>

## Réhébergement de WebAssembly pour échapper à l’analyse statique

Au lieu de modifier un outil Go lourdement associé à des signatures, il est possible de le compiler comme invité `wasip1` et de l’intégrer dans un chargeur natif distinct. L’invité est compilé avec un GOROOT patché, dans lequel les opérations non prises en charge, telles que `net.Dial`, `net.Listen`, `os/exec` et `os.Pipe`, sont déléguées via `//go:wasmimport` ; un module hôte Wazero implémente ensuite les sockets, les opérations sur les processus, les appels Win32 et les appels aux frameworks macOS. Cela préserve l’utilisation de l’API Go d’origine du projet tout en déplaçant l’essentiel de sa logique dans un module WASM chiffré que les outils statiques pour PE peuvent ne pas comprendre.<sup>[[4]](#references)</sup>

### Relier la mémoire linéaire aux API natives

Un pointeur d’invité est un décalage de 32 bits dans la mémoire linéaire WASM, et non une adresse virtuelle de l’hôte. Avant un appel natif, le pont peut traduire un argument uniquement s’il est marqué comme pointeur local et se trouve dans la plage `0x10000 <= value < wasmMemorySize`, pour produire `wasmMemoryBase + value`. La limite inférieure évite de réécrire les petits handles, les flags et `nil` ; des masques par API générés à partir de `win32metadata` distinguent les vrais pointeurs des handles, des tailles et des adresses de processus distant, avec des exceptions pour les métadonnées inexactes ou ambiguës.<sup>[[4]](#references)</sup>

Les API natives peuvent également renvoyer des pointeurs hôte via les tampons de sortie de l’invité. Une table miroir peut attribuer à ces objets des représentations en mémoire invitée et conserver une correspondance inverse vers l’adresse hôte d’origine. COM nécessite la mise en miroir de l’interface et de sa vtable : les pointeurs de données peuvent être suivis et mis en miroir, tandis que les pointeurs exécutables dans les régions `MEM_IMAGE` doivent rester des jetons opaques, car WASM ne peut pas exécuter d’instructions natives. Ce modèle ne prend pas directement en charge les API de rappel de l’hôte vers l’invité, telles que `EnumWindows` ou `SetWindowsHookEx`.<sup>[[4]](#references)</sup>

### Polymorphisme de la VM WASM à chaque build

Le runtime et le payload peuvent être transformés ensemble à chaque build : mélanger la table associant les opcodes aux handlers, réécrire chaque opcode invité selon la nouvelle correspondance, randomiser les identifiants de section, remplacer la signature standard `\0asm` par un marqueur propre au build et modifier la signature du cache du runtime. Un même code source produit ainsi des modules différents octet par octet, et les outils WASM courants ne peuvent pas analyser le payload tant que l’analyste n’a pas retrouvé la correspondance personnalisée et le cadrage à partir du chargeur hôte.<sup>[[4]](#references)</sup>

Pour la rétro-ingénierie, commencez par examiner l’hôte natif plutôt que de rechercher uniquement la signature `\0asm` : repérez le marqueur compilé, le chemin de déchiffrement du module, la table de dispatch des opcodes et les enregistrements des host functions `env`, puis reconstruisez un module standard ou instrumentez la frontière d’import. Le pont reste un point de contrôle comportemental utile, car les appels réseau, la création de processus, l’accès au registre, le chargement dynamique et le dispatch Win32 générique le traversent, même lorsque le bytecode intégré change d’un build à l’autre.<sup>[[4]](#references)</sup>

### Camoufler l’exécutable Go externe

Modifier uniquement l’invité laisse un chargeur reconnaissable. Les transformations démontrées insèrent dans `gopclntab` des profils de symboles denses prélevés sur des projets Go légitimes, font tourner un petit ensemble plausible d’imports DLL et modifient `VERSIONINFO` du PE ainsi que les chaînes d’identité Authenticode. Ces transformations ciblent les caractéristiques statiques et d’apprentissage automatique du conteneur ; elles ne suppriment pas le comportement d’exécution exposé par les shims hôte.<sup>[[4]](#references)</sup>

## Modèle d’exécution

Un chargeur virtualisé compact peut répartir l’exécution sur les couches suivantes.<sup>[[3]](#references)</sup>

1. Compiler du C freestanding, du code source BOF ou des bibliothèques runtime via LLVM vers une ISA bytecode personnalisée.
2. Démarrer un petit interpréteur natif et initialiser une correspondance d’opcodes propre au build.
3. Exécuter le chargeur PE-linker lui-même en bytecode : analyser les en-têtes, mapper les sections, appliquer les relocations, résoudre les imports et remplir l’IAT.
4. Maintenir les appels invité-à-invité dans l’interpréteur. Acheminer les cibles situées hors de la région bytecode, comme les fonctions de DLL importées, via un thunk d’appel hôte natif.
5. Placer les fonctions auxiliaires, comme le cadrage HTTP, TLS et certaines parties du runtime C, derrière la même frontière d’interprétation.

Ce modèle évite d’allouer une région de code native distincte pour chaque plugin et empêche le payload d’origine d’apparaître sous la forme d’un flux d’instructions x86-64 reconnaissable. Il s’agit néanmoins d’une frontière d’évasion/d’obfuscation, et non d’une frontière de sécurité : l’interpréteur natif et tous les effets externes restent observables.<sup>[[2]](#references)[[3]](#references)</sup>

## Pont hôte à mémoire partagée

Une VM isolée représente les pointeurs par des décalages dans un tampon invité ; chaque appel à une API hôte nécessite donc une traduction des pointeurs et un traitement spécifique des paramètres de sortie. Une VM à mémoire partagée rend au contraire les adresses invitées valides dans le processus hôte. Les lectures et écritures peuvent donc utiliser des opérations de type `memcpy`, et un pointeur renvoyé par un ECALL d’allocation native peut être directement déréférencé par le bytecode. RISC-Y Business a montré que cette conception pouvait réduire le pont à l’obtention du PEB et à l’émission d’appels hôte arbitraires.<sup>[[1]](#references)</sup>

Sous Windows x64, le fichier de registres virtuels peut refléter l’ABI : placer les quatre premiers arguments entiers ou pointeurs dans `RCX`, `RDX`, `R8` et `R9`, puis les arguments suivants et l’espace shadow sur la pile. Lorsqu’un `CALL` virtuel résout une cible située hors de la plage bytecode, un thunk universel transmet cet état à un appel natif et recopie la valeur de retour dans la VM. Cela permet les appels IAT, l’allocation sur le tas et les opérations sur les sockets sans correction des pointeurs.<sup>[[2]](#references)[[3]](#references)</sup>

Le compromis est la perte totale de l’isolation. Une corruption de la mémoire invitée peut affecter directement l’hôte, les fonctions natives appelées peuvent conserver ou modifier les pointeurs invités, et l’interpréteur doit considérer le bytecode comme entièrement fiable. Les callbacks natif-vers-VM nécessitent également un pont inverse ; une VM qui ne prend en charge que les appels sortants ne peut pas satisfaire directement les API reposant sur des callbacks, comme `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polymorphisme de l’ISA à chaque build

Une ISA personnalisée à largeur fixe simplifie le décodage, le dispatch, les relocations et le mappage des registres virtuels. Centurion utilise un format d’instruction de 18 octets inspiré de x86-64, qui privilégie un parsing prévisible au détriment de la densité du code et offre également une voie possible pour convertir en bytecode des artefacts x86-64 existants.<sup>[[3]](#references)</sup>

Randomiser la correspondance entre opcodes et handlers à chaque build fait produire des séquences d’octets différentes à une même logique invitée. Chiffrer la table de correspondance et ne la récupérer qu’à l’exécution élimine davantage encore tout dictionnaire d’opcodes stable sur disque. Cela complique les signatures fixes et les règles de désassemblage réutilisables, mais ne polymorphise pas automatiquement le dispatcher natif, la routine de déchiffrement de la table ni la frontière des appels hôte.<sup>[[3]](#references)</sup>

## Intégrer l’environnement d’exécution à la VM

Le processus hôte peut être réduit à des primitives de mémoire, de syscall et de socket, tandis que des bibliothèques freestanding fournissent des services de plus haut niveau dans la VM. Par exemple, FreeRTOS coreHTTP peut gérer le cadrage HTTP et mbedTLS le TLS, sans appeler WinHTTP ni une API TLS du système d’exploitation. Les sockets bruts via `afd.sys` ou une interface similaire constituent alors la frontière réseau native restreinte.<sup>[[3]](#references)</sup>

Cette conception **Bring Your Own Execution Environment (BYOEE)** peut également placer le chargement de PE, le support du runtime et un système de fichiers en mémoire derrière l’interpréteur. Elle réduit le recours à des implémentations natives reconnaissables, mais n’élimine pas la télémétrie : les opérations sur les sockets bruts restent visibles, et les environnements qui exigent des proxys explicites ou l’interception TLS peuvent empêcher le fonctionnement de cette conception réseau.<sup>[[3]](#references)</sup>

## Accélération native sélective

L’interprétation de chaque instruction est particulièrement coûteuse en cryptographie à clé publique. Une séparation pratique utilise les hooks `MBEDTLS_ALT` de mbedTLS comme interface de coprocesseur logiciel : conserver l’état TLS, l’analyse des certificats, la négociation, l’allocation et le code bignum de haut niveau en bytecode, mais dispatcher les kernels arithmétiques les plus sollicités de `bignum_core.c` via des ECALL natifs. Dans le prototype Centurion, `bignum.c`, `bignum_mod.c` et `bignum_mod_raw.c` restaient virtualisés tandis que les boucles internes s’exécutaient nativement, ce qui réduisait une négociation ECDHE de plusieurs minutes à quelques secondes.<sup>[[3]](#references)</sup>

Rendez les accélérateurs facultatifs afin que les payloads qui n’ont pas besoin de TLS omettent les points d’entrée natifs supplémentaires. Cette approche s’applique à toute charge de travail d’interpréteur : commencez par profiler, puis exposez la primitive native la plus réduite possible au lieu de déplacer tout un sous-système hors de la VM.<sup>[[3]](#references)</sup>

Centurion a validé la chaîne complète avec un bind shell TLS 1.2 : le chargeur bytecode a mappé le PE, les appels socket ont traversé le thunk universel, mbedTLS a géré le protocole dans la VM et des ECALL natifs ont accéléré l’arithmétique ECDHE. L’interpréteur natif d’environ 18 Ko a donc pris en charge un canal de commande chiffré sans matérialiser le payload sous forme de code x86-64 natif.<sup>[[3]](#references)</sup>

## Points d’ancrage pour l’analyse et la détection

Les éléments suivants sont des points d’ancrage pratiques pour l’analyse, déduits de l’architecture ; la virtualisation déplace les endroits où les analystes observent le comportement, mais ne supprime pas ce comportement.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Repérer la boucle de fetch/decode/dispatch, le compteur de programme virtuel, le fichier de registres et l’avancement répété par instructions de largeur fixe.
- Extraire la table des opcodes après son déchiffrement à l’exécution et associer les adresses des handlers à leurs opérations sémantiques, plutôt que de rechercher des correspondances avec le bytecode chiffré sur disque.
- Placer un point d’arrêt sur le thunk universel ou le dispatcher ECALL afin d’enregistrer la cible native, les registres d’arguments virtuels, les arguments sur la pile et la valeur de retour.
- Tracer l’accès au PEB, la résolution des exports, l’analyse des en-têtes PE, les écritures de relocations et le remplissage de l’IAT, même lorsque l’implémentation du chargeur est elle-même en bytecode.
- Corréler la création de sockets et le trafic `afd.sys` avec l’absence d’appels WinHTTP ou TLS natifs attendus ; l’absence d’imports de haut niveau est un indice, pas une preuve d’activité bénigne.
- Considérer les accélérateurs arithmétiques natifs comme des points de contrôle sémantiques : leurs appelants peuvent révéler l’échange de clés et l’activité de validation des certificats, tandis que la machine à états TLS environnante reste virtualisée.

Pour les flux d’analyse qui partent du dispatcher plutôt que du graphe de flot de contrôle d’origine, consultez les [recommandations d’analyse de malware pour la virtualisation des packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Contraintes opérationnelles

La virtualisation entraîne un surcoût d’interprétation, augmente la complexité de la toolchain et de l’ABI, et ne résout pas la détection comportementale. La mémoire partagée est dangereuse par conception, le réseau via des sockets bruts peut échouer derrière des proxys obligatoires et les API Win32 reposant fortement sur des callbacks nécessitent des trampolines natif-vers-VM. L’interpréteur, le pont syscall et les accélérateurs natifs restent également une empreinte native conventionnelle que les défenseurs peuvent identifier par signature ou instrumenter.<sup>[[2]](#references)[[3]](#references)</sup>

## Pages connexes

Pour l’analyse du packing VMProtect 3.x, consultez [décompression émulée et réparation des imports](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair).

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business : création d’une machine virtuelle RISC-V pour l’obfuscation de payload](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT : Red Teaming à l’ère de l’EDR — évasion par la virtualisation de malware](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian : Centurion — apporter son propre environnement d’exécution](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - Entrez dans WasmForge : compiler Sliver en WebAssembly](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
