# Rootkits du noyau Windows et DKOM

{{#include ../../banners/hacktricks-training.md}}

## Portée

Un implant déployé après compromission peut charger un pilote noyau signé en tant que service et exposer un plan de contrôle en user-mode via `IRP_MJ_DEVICE_CONTROL`. La signature du pilote établit uniquement que Windows accepte l’image ; elle ne garantit pas que l’autorisation des IOCTL, les opérations mémoire, les callbacks ou les hooks sont sûrs. Un rootkit analysé utilisait trois handlers en fonctionnement normal, mais exposait des dizaines de primitives supplémentaires de post-exploitation. La rétro-ingénierie doit donc couvrir l’ensemble du dispatcher, et pas seulement les requêtes observées dans une trace de malware.<sup>[[1]](#references)</sup>

## Triage des pilotes signés et des IOCTL

Commencez par `DriverEntry`, consignez les objets de périphérique et les liens symboliques DOS, localisez la routine `MajorFunction[IRP_MJ_DEVICE_CONTROL]`, puis répertoriez chaque comparaison et entrée de table menant à un handler. Comparez les noms ouverts par le user-mode aux noms réellement créés par le pilote : une chaîne observée ouvrait `\\.\msagent`, tandis que son pilote créait `\Device\ToolTool` et `\DosDevices\ToolTool`. Cette incohérence peut révéler un autre échantillon ou une autre configuration, une logique d’installation manquante ou une incohérence dans l’analyse.<sup>[[1]](#references)</sup>

Décodez chaque code de contrôle avant de reconstruire sa structure d’entrée.<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

Ces trois codes se décodent en `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` et `METHOD_BUFFERED`. Cela ne prouve **pas** qu’un appelant non privilégié peut y accéder : examinez également la DACL du périphérique, les dispatch routines de création/ouverture, les vérifications de l’appelant pour chaque requête, les longueurs de buffer attendues, les pointeurs intégrés, la gestion de la durée de vie des PID et si le handler fait confiance à un PID ou à un flag fourni par l’appelant.<sup>[[1]](#references)</sup>

Lorsque l’implant n’utilise qu’un sous-ensemble de commandes, regroupez les autres handlers par primitive au lieu de les considérer comme du code mort. Un seul driver multifonction a exposé toutes les catégories suivantes :<sup>[[1]](#references)</sup>

- **Contrôle/configuration :** activer ou désactiver l’état du rootkit ; ajouter, supprimer, interroger ou effacer les chemins, processus et adresses C2 protégés.
- **Manipulation de processus :** terminer un PID, démapper son image, injecter avec `NtCreateThreadEx`, masquer/restaurer des processus ou des modules utilisateur, et supprimer la protection PPL.
- **Manipulation du kernel :** délier un driver chargé, énumérer/désactiver/restaurer des callbacks de notification, mapper manuellement un autre driver et écrire à une adresse arbitraire du kernel.
- **Manipulation d’objets :** supprimer/déchiffrer des fichiers et créer ou modifier des valeurs de registre.

## Mapping manuel du kernel via un driver signé vulnérable

Un driver signé disposant d’opérations de lecture/écriture de la mémoire du kernel peut servir de loader pour une image de driver non signée, sans demander à Windows de charger cette image comme un driver normal.<sup>[[2]](#references)[[7]](#references)</sup> L’exemple LocalStranger ouvre un périphérique `\\.\WinNotify` existant ; son code source ne montre pas qu’un utilisateur non privilégié peut installer, démarrer ou ouvrir le driver sur un hôte quelconque.<sup>[[2]](#references)[[3]](#references)</sup> Le mapper prend un chemin d’image, récupère l’adresse de base du kernel chargé et utilise les IOCTL de lecture/écriture de mémoire virtuelle du périphérique.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

Pour transformer cet accès en lecture/écriture en appel kernel, le mapper lit une valeur immédiate de base PTE dans `MmGetVirtualForPhysical` et parcourt les entrées de pagination couvrant `NtAddAtom`.<sup>[[5]](#references)[[7]](#references)</sup> Son calcul de PTE est `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)` ; le code vérifie également la présence d’un PDE de grande page.<sup>[[5]](#references)[[7]](#references)</sup> Il rend temporairement inscriptible l’entrée couvrante, remplace l’entrée syscall par un saut vers la fonction kernel souhaitée, appelle le stub utilisateur `NtAddAtom`, puis restaure les octets et l’entrée de page d’origine.<sup>[[6]](#references)</sup>

Le mapper utilise ce chemin d’appel pour `ExAllocatePool`, mappe les sections PE, les imports et les relocations dans l’image, l’écrit dans l’allocation et appelle son point d’entrée.<sup>[[7]](#references)[[8]](#references)</sup> Cette implémentation n’accepte que les images PE x64 relogeables ; sa lecture de la base PTE suppose également un agencement fixe `MmGetVirtualForPhysical + 34`.<sup>[[5]](#references)[[8]](#references)</sup> Considérez-la comme dépendante de la build, et non comme un contournement indépendant de KASLR ou une preuve que HVCI ou PatchGuard autorise le mapping.<sup>[[5]](#references)[[8]](#references)</sup> Pour un usage de kernel R/W limité aux données, consultez [vol de token SYSTEM](arbitrary-kernel-rw-token-theft.md).

## Exemptions pour les processus de confiance

Un modèle de conception utile est un IOCTL qui enregistre un PID accompagné d’un flag **trusted**. La même vérification de confiance est ensuite utilisée par les filtres de fichiers, de registre, de processus et de threads : les outils non fiables reçoivent des résultats d’énumération filtrés, des droits d’accès aux handles réduits ou `STATUS_ACCESS_DENIED`, tandis que l’implant peut toujours mettre à jour ses propres objets cachés. Traitez cela comme une frontière d’autorisation et vérifiez comment les entrées sont authentifiées, synchronisées et supprimées après la fin du processus ou la réutilisation du PID.<sup>[[1]](#references)</sup>

Les rootkits peuvent conserver leur stratégie dans des valeurs `REG_MULTI_SZ` et compiler des listes de fichiers, répertoires, clés de registre, valeurs de registre, images ignorées, images protégées et images cachées dans des arbres AVL. Pendant l’analyse, suivez tous les lecteurs et écrivains de ces arbres partagés ; ils relient la configuration du registre, les IOCTL, les callbacks et la logique de filtrage, même lorsque les noms de fonctions ont été supprimés.<sup>[[1]](#references)</sup>

## Masquage de processus et de modules par DKOM

### `EPROCESS.ActiveProcessLinks`

Les offsets de `ActiveProcessLinks` varient selon la build de Windows. Un rootkit tolérant aux versions peut tester des candidats connus, puis parcourir `EPROCESS` à la recherche d’un `LIST_ENTRY` cohérent dont les voisins pointent vers le candidat. Il conserve l’offset découvert, masque un processus en reconnectant les `Flink`/`Blink` de ses voisins et préserve l’état nécessaire pour relier l’entrée ultérieurement. Le processus continue de s’exécuter, mais disparaît des énumérateurs qui parcourent la liste des processus actifs.<sup>[[1]](#references)</sup>

Il s’agit de **DKOM**, pas d’une terminaison. La détection doit comparer les résultats fondés sur les listes à des preuves indépendantes, telles que les scans de pool/d’objets, la propriété des threads, les tables de handles, les artefacts du scheduler et l’inspection de la mémoire du kernel. Un processus visible lors d’un scan mais absent de la liste canonique est plus révélateur que l’une ou l’autre vue prise isolément.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

La primitive équivalente de masquage de module trouve l’entrée cible dans `PsLoadedModuleList` et modifie les pointeurs `Flink`/`Blink` adjacents. Le driver reste mappé et exécutable, mais les requêtes de modules fondées sur la liste ne le renvoient plus. Comparez la liste du loader aux mappings exécutables du kernel, aux tags de pool, aux objets de périphériques/drivers, aux clés de service, aux adresses de callbacks et aux pointeurs de dispatch qui pointent hors d’une image répertoriée.<sup>[[1]](#references)</sup>

## Protection et dissimulation par callbacks

Un rootkit peut combiner des frameworks de callbacks documentés avec DKOM et des hooks :<sup>[[1]](#references)</sup>

- Les handlers de pré-opération `ObRegisterCallbacks` pour `PsProcessType` et `PsThreadType` suppriment les droits utilisés pour la terminaison, l’accès à la VM, la duplication ou la manipulation de threads lorsqu’un appelant non fiable ouvre une cible protégée. Notez l’altitude du callback et identifiez le module propriétaire de chaque adresse de callback.
- `PsSetCreateProcessNotifyRoutineEx` et `PsSetLoadImageNotifyRoutine` maintiennent l’état des processus protégés/ignorés/cachés à mesure que des processus et des images apparaissent ; un parcours ponctuel des processus peut compléter les objets existant avant l’enregistrement.
- Un minifilter de système de fichiers refuse l’accès aux chemins configurés. Une implémentation inhabituelle peut créer sa clé `Instances`, choisir une altitude de manière dynamique et l’incrémenter puis réessayer lorsque `FltRegisterFilter` signale une collision.
- Une routine `CmRegisterCallbackEx` peut supprimer les noms protégés des résultats d’énumération et refuser les opérations directes d’ouverture, de renommage, de définition ou de suppression, tout en exemptant les processus de confiance enregistrés.

Mettez en corrélation les enregistrements `ObRegisterCallbacks`, les altitudes des callbacks du registre, la sortie de `fltmc filters`, les clés de service `Instances` et les adresses des callbacks. Si les outils habituels sont filtrés, inspectez ces structures à partir d’une image mémoire hors ligne ou d’une autre couche d’acquisition fiable.<sup>[[1]](#references)</sup>

## Filtrage des résultats de Nsiproxy

La dissimulation du réseau peut cibler `\Driver\Nsiproxy` : récupérer l’objet driver avec `ObReferenceObjectByName`, enregistrer un pointeur de handler, le remplacer par un wrapper et supprimer les enregistrements IPv4 renvoyés qui correspondent à une liste C2 gérée par IOCTL avant que le mode utilisateur ne les reçoive. Les applications qui s’appuient sur les données NSI filtrées peuvent ne plus afficher la connexion, même si le trafic existe toujours.<sup>[[1]](#references)</sup>

Comparez les vues des connexions de l’hôte à la capture de paquets, à la télémétrie WFP/ETW et aux objets réseau en mémoire du kernel. Inspectez également les pointeurs de dispatch/handler de `Nsiproxy` et vérifiez que chacun pointe dans le module signé attendu ; un pointeur vers un mapping non répertorié peut relier le filtrage réseau au DKOM de `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Liste de vérification pour l’investigation

Le signal le plus fort est un désaccord entre les couches, pas un nom de fichier ou un hash isolé. Mettez en corrélation :<sup>[[1]](#references)</sup>

1. La création d’un service kernel et un driver signé dont l’ancienneté du certificat, l’éditeur ou le chemin ne correspondent pas au produit installé.
2. La création de périphériques, les liens DOS et le trafic IOCTL, notamment les divergences entre les noms de périphériques en mode utilisateur et dans le kernel.
3. Une requête d’enregistrement de PID suivie d’échecs, pour d’autres processus, à ouvrir, énumérer, modifier ou supprimer les mêmes objets.
4. Les callbacks d’objets/registre/processus/images, les instances de minifilter et les hooks dont les adresses n’appartiennent pas à un driver normalement énuméré.
5. Les différences entre les inventaires de processus, modules, callbacks et réseaux fondés sur des listes et ceux fondés sur des scans.

## References

- [1] [Kaspersky Securelist - HoneyMyte améliore CoolClient avec un rootkit signé du kernel Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [README de LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [Initialisation du driver LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [Ligne de commande du mapper LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [Résolution des exports du kernel et de la base PTE dans LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [Trampoline d’appel au kernel de LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [Allocation et appel du point d’entrée par le mapper LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [Mapping PE de LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [Contexte du kernel et des syscalls dans LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [Wrappers IOCTL de mémoire virtuelle de LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
