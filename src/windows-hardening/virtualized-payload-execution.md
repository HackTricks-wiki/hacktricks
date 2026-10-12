# Exécution de Payload virtualisé et évasion par VM personnalisée

{{#include ../banners/hacktricks-training.md}}

La virtualisation de Payload compile la logique offensive en un jeu d’instructions invité et l’exécute avec un interpréteur natif. Contrairement à un packer, qui doit finir par exposer les instructions natives d’origine en mémoire, un Payload virtualisé peut conserver la logique protégée sous forme de bytecode pendant toute son exécution. Cela supprime cette fenêtre spécifique de dépaquetage, mais ne masque **pas** les comportements visibles par l’hôte, comme les syscalls, l’activité réseau ou la frontière entre VM et appels natifs.<sup>[[2]](#references)[[3]](#references)</sup>

## Modèle d’exécution

Un loader virtualisé compact peut répartir l’exécution dans les couches suivantes.<sup>[[3]](#references)</sup>

1. Compiler du C freestanding, du code source BOF ou des bibliothèques runtime en passant par LLVM pour obtenir une ISA bytecode personnalisée.
2. Démarrer un petit interpréteur natif et initialiser un mappage d’opcodes spécifique au build.
3. Exécuter le linker-loader PE lui-même en bytecode : analyser les en-têtes, mapper les sections, appliquer les relocations, résoudre les imports et renseigner l’IAT.
4. Maintenir les appels invité-à-invité dans l’interpréteur. Acheminer les cibles situées hors de la plage bytecode, comme les fonctions de DLL importées, via un thunk d’appel natif.
5. Placer également derrière la même frontière d’interprétation les fonctions auxiliaires telles que le framing HTTP, TLS et certaines parties du runtime C.

Ce modèle évite d’allouer une région de code natif distincte pour chaque plugin et empêche le Payload d’origine d’apparaître sous la forme d’un flux d’instructions x86-64 reconnaissable. Il constitue néanmoins une frontière d’évasion et d’obfuscation, pas une frontière de sécurité : l’interpréteur natif et chaque effet externe restent observables.<sup>[[2]](#references)[[3]](#references)</sup>

## Bridge hôte à mémoire partagée

Une VM isolée représente les pointeurs par des offsets dans un buffer invité ; chaque appel à une API hôte nécessite donc une traduction des pointeurs et un traitement spécial des paramètres de sortie. À l’inverse, une VM à mémoire partagée rend les adresses invité valides dans le processus hôte. Les lectures et écritures peuvent alors utiliser des opérations de type `memcpy`, et le bytecode peut déréférencer directement un pointeur renvoyé par un ECALL d’allocation natif. RISC-Y Business a montré que cette conception peut réduire le bridge à la récupération du PEB et à l’exécution d’appels hôte arbitraires.<sup>[[1]](#references)</sup>

Sous Windows x64, le fichier de registres virtuels peut reproduire l’ABI : placer les quatre premiers arguments entiers ou pointeurs dans `RCX`, `RDX`, `R8` et `R9`, puis placer les arguments suivants et le shadow space sur la pile. Lorsqu’un `CALL` virtuel cible une adresse située hors de la plage bytecode, un thunk universel marshalise cet état pour exécuter un appel natif et copie la valeur de retour dans la VM. Cela permet les appels via l’IAT, l’allocation du tas et les opérations socket sans correction de pointeurs.<sup>[[2]](#references)[[3]](#references)</sup>

Le compromis est une perte totale d’isolation. Une corruption de la mémoire invitée peut affecter directement l’hôte, les fonctions natives appelées peuvent conserver ou modifier des pointeurs invités, et l’interpréteur doit considérer le bytecode comme entièrement fiable. Les callbacks natifs vers la VM nécessitent également un bridge inverse ; une VM qui ne prend en charge que les appels sortants ne peut pas directement répondre aux API basées sur des callbacks, telles que `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polymorphisme de l’ISA par build

Une ISA personnalisée à largeur fixe simplifie le décodage, le dispatch, les relocations et le mappage des registres virtuels. Centurion utilise un format d’instruction de 18 octets inspiré de x86-64. Il sacrifie la densité du code au profit d’une analyse prévisible et offre aussi une voie possible pour traduire des artefacts x86-64 existants en bytecode.<sup>[[3]](#references)</sup>

La randomisation du mappage opcode-handler à chaque build fait produire des séquences d’octets différentes à une même logique invitée. Chiffrer la table de mappage et ne la récupérer qu’au runtime élimine en outre tout dictionnaire d’opcodes stable sur disque. Cela complique les signatures fixes et les règles de désassemblage réutilisables, mais ne polymorphise pas automatiquement le dispatcher natif, la routine de déchiffrement de la table ni la frontière des appels hôte.<sup>[[3]](#references)</sup>

## Intégrer l’environnement d’exécution à la VM

Le processus hôte peut être réduit à des primitives de mémoire, de syscall et de socket, tandis que des bibliothèques freestanding fournissent des services de plus haut niveau dans la VM. Par exemple, FreeRTOS coreHTTP peut gérer le framing HTTP et mbedTLS le TLS, sans appeler WinHTTP ni une API TLS du système d’exploitation. Les sockets bruts via `afd.sys` ou une interface similaire deviennent alors la frontière réseau native restreinte.<sup>[[3]](#references)</sup>

Cette conception **Bring Your Own Execution Environment (BYOEE)** peut également placer le chargement PE, le support du runtime et un système de fichiers en mémoire derrière l’interpréteur. Elle réduit la présence d’implémentations natives reconnaissables sans éliminer la télémétrie : les opérations socket brutes restent visibles, et les environnements qui exigent des proxies explicites ou l’interception TLS peuvent empêcher le fonctionnement de cette conception réseau.<sup>[[3]](#references)</sup>

## Accélération native sélective

L’interprétation de chaque instruction est particulièrement coûteuse en cryptographie à clé publique. Une répartition pratique utilise les hooks `MBEDTLS_ALT` de mbedTLS comme interface de coprocesseur logiciel : conserver dans le bytecode l’état TLS, l’analyse des certificats, la négociation, l’allocation et le code bignum de haut niveau, mais dispatcher les kernels arithmétiques les plus sollicités de `bignum_core.c` via des ECALL natifs. Dans le prototype Centurion, `bignum.c`, `bignum_mod.c` et `bignum_mod_raw.c` sont restés virtualisés, tandis que les boucles internes s’exécutaient nativement, réduisant un handshake ECDHE de plusieurs minutes à quelques secondes.<sup>[[3]](#references)</sup>

Rendez les accélérateurs optionnels afin que les Payloads qui n’ont pas besoin de TLS n’incluent pas de points d’entrée natifs supplémentaires. Ce modèle s’applique à toute charge de travail d’interpréteur : commencez par profiler, puis exposez la primitive native la plus petite possible au lieu de déplacer tout un sous-système hors de la VM.<sup>[[3]](#references)</sup>

Centurion a validé la chaîne complète avec un bind shell TLS 1.2 : le loader bytecode a mappé le PE, les appels socket ont traversé le thunk universel, mbedTLS a géré le protocole dans la VM et des ECALL natifs ont accéléré l’arithmétique ECDHE. L’interpréteur natif d’environ 18 Ko a ainsi pris en charge un canal de commande chiffré sans matérialiser le Payload sous forme de code x86-64 natif.<sup>[[3]](#references)</sup>

## Repères pour l’analyse et la détection

Voici des repères pratiques d’analyse déduits de l’architecture ; la virtualisation modifie l’endroit où les analystes observent le comportement, mais ne supprime pas ce comportement.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Identifiez la boucle fetch/decode/dispatch, le compteur de programme virtuel, le fichier de registres et l’avancement répété par instructions de largeur fixe.
- Extrayez la table d’opcodes après son déchiffrement au runtime et associez les adresses des handlers à leurs opérations sémantiques, au lieu de chercher des correspondances dans le bytecode chiffré sur disque.
- Placez un breakpoint sur le thunk universel ou le dispatcher ECALL pour enregistrer la cible native, les registres d’arguments virtuels, les arguments de pile et la valeur de retour.
- Tracez l’accès au PEB, la résolution des exports, l’analyse des en-têtes PE, l’écriture des relocations et le remplissage de l’IAT, même lorsque l’implémentation du loader est elle-même en bytecode.
- Corrélez la création de sockets et le trafic `afd.sys` à l’absence d’appels WinHTTP ou TLS natifs attendus ; l’absence de ces imports de haut niveau est un indice, pas une preuve d’un comportement bénin.
- Traitez les accélérateurs arithmétiques natifs comme des points de contrôle sémantiques : leurs appelants peuvent révéler les échanges de clés et la validation des certificats, tandis que la machine à états TLS environnante reste virtualisée.

Pour les workflows d’analyse qui partent du dispatcher plutôt que du graphe de flot de contrôle d’origine, consultez les [conseils d’analyse de malware pour les packers virtualisés](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Contraintes opérationnelles

La virtualisation entraîne une surcharge d’interprétation, augmente la complexité de la toolchain et de l’ABI, et ne résout pas la détection comportementale. La mémoire partagée est dangereuse par conception, le réseau par sockets bruts peut échouer derrière des proxies obligatoires, et les API Win32 reposant sur de nombreux callbacks nécessitent des trampolines natifs vers la VM. L’interpréteur, le bridge syscall et les éventuels accélérateurs natifs restent également une empreinte native conventionnelle que les défenseurs peuvent reconnaître par signature ou instrumenter.<sup>[[2]](#references)[[3]](#references)</sup>

## Pages associées

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business : créer une machine virtuelle RISC-V pour l’obfuscation de Payload](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT : le Red Teaming à l’ère de l’EDR — l’évasion par la virtualisation de malware](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian : Centurion — apporter son propre environnement d’exécution](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
