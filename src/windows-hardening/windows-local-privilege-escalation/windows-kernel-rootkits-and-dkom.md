# Rootkits du kernel Windows et DKOM

{{#include ../../banners/hacktricks-training.md}}

## Scope

Un implant post-compromise peut charger un signed kernel driver en tant que service et exposer un control plane en user mode via `IRP_MJ_DEVICE_CONTROL`. La signature du driver établit uniquement que Windows accepte l'image ; elle ne garantit pas que l'autorisation des IOCTL, les opérations mémoire, les callbacks ou les hooks sont sûrs. Un rootkit analysé utilisait trois handlers pendant son fonctionnement normal, mais exposait des dizaines de primitives supplémentaires de post-exploitation. Le reverse engineering doit donc couvrir l'intégralité du dispatcher, plutôt que seulement les requêtes observées dans une trace de malware.<sup>[[1]](#references)</sup>

## Triage des signed drivers et des IOCTL

Commencez par `DriverEntry`, notez les objets device et les liens symboliques DOS, localisez la routine `MajorFunction[IRP_MJ_DEVICE_CONTROL]` et cartographiez chaque comparaison ou entrée de table qui mène à un handler. Comparez les noms ouverts par le user mode avec les noms réellement créés par le driver : une chaîne observée ouvrait `\\.\msagent`, tandis que son driver créait `\Device\ToolTool` et `\DosDevices\ToolTool`. Cette différence peut permettre d'identifier un autre échantillon ou une autre configuration, une logique de setup manquante ou une incohérence dans l'analyse.<sup>[[1]](#references)</sup>

Décodez chaque control code avant de reconstruire sa structure d'entrée.<sup>[[1]](#references)</sup>
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
Ces trois codes se décodent respectivement en `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` et `METHOD_BUFFERED`. Cela ne prouve **pas** qu’un appelant non privilégié puisse les atteindre : examinez également la DACL du device, la création/l’ouverture et le dispatch, les vérifications de l’appelant pour chaque requête, les longueurs de buffer attendues, les pointeurs intégrés, la gestion de la durée de vie des PID, ainsi que le fait que le handler fasse confiance ou non à un PID ou à un flag fourni par l’appelant.<sup>[[1]](#references)</sup>

Lorsque l’implant n’utilise qu’un sous-ensemble de commandes, regroupez les handlers restants par primitive au lieu de les considérer comme du dead code. Un seul multifunction driver a exposé toutes les classes suivantes :<sup>[[1]](#references)</sup>

- **Contrôle/configuration :** activer ou désactiver l’état du rootkit ; ajouter, supprimer, interroger ou effacer les chemins, processus et adresses C2 protégés.
- **Manipulation des processus :** terminer un PID, désmapper son image, injecter avec `NtCreateThreadEx`, masquer/restaurer des processus ou des modules utilisateur, et supprimer la protection PPL.
- **Manipulation du kernel :** retirer un driver chargé d’une liste chaînée, énumérer/désactiver/restaurer les notification callbacks, mapper manuellement un autre driver et écrire à une adresse kernel arbitraire.
- **Manipulation des objets :** supprimer/déchiffrer des fichiers et créer ou modifier des valeurs de registre.

## Exemptions des trusted processes

Un modèle de conception utile consiste en un IOCTL qui enregistre un PID avec un flag **trusted**. La même recherche de confiance est ensuite consultée par les filtres de fichiers, de registre, de processus et de threads : les outils untrusted reçoivent des résultats d’énumération filtrés, des droits de handle réduits ou `STATUS_ACCESS_DENIED`, tandis que l’implant peut toujours mettre à jour ses propres objets masqués. Considérez cela comme une frontière d’autorisation et vérifiez comment les entrées sont authentifiées, synchronisées et supprimées après la sortie du processus ou la réutilisation du PID.<sup>[[1]](#references)</sup>

Les rootkits peuvent conserver une policy dans des valeurs `REG_MULTI_SZ` et compiler les listes de fichiers, répertoires, registry keys, registry values, ignored images, protected images et hidden images dans des arbres AVL. Pendant l’analyse, tracez chaque lecteur et écrivain de ces arbres partagés ; cela relie la configuration du registre, les IOCTLs, les callbacks et la logique de filtrage, même lorsque les noms de fonctions ont été supprimés.<sup>[[1]](#references)</sup>

## Masquage des processus et modules par DKOM

### `EPROCESS.ActiveProcessLinks`

Les offsets de `ActiveProcessLinks` varient selon la build de Windows. Un rootkit tolérant aux versions peut tester les candidats connus, puis parcourir `EPROCESS` à la recherche d’un `LIST_ENTRY` cohérent dont les voisins pointent vers le candidat. Il conserve l’offset découvert, masque un processus en reconnectant les `Flink`/`Blink` de ses voisins et préserve l’état nécessaire pour relier à nouveau l’entrée ultérieurement. Le processus continue de s’exécuter, mais disparaît des énumérateurs qui parcourent la liste des processus actifs.<sup>[[1]](#references)</sup>

Il s’agit de **DKOM**, et non d’une terminaison. La détection doit comparer les résultats fondés sur les listes avec des éléments indépendants, comme les scans de pool/objets, la propriété des threads, les tables de handles, les artefacts du scheduler et l’inspection de la mémoire kernel. Un processus visible lors d’un scan mais absent de la liste canonique est plus significatif que l’une ou l’autre vue prise isolément.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

La primitive équivalente de masquage de modules trouve l’entrée cible dans `PsLoadedModuleList` et modifie les pointeurs `Flink`/`Blink` adjacents. Le driver reste mappé et exécutable, mais les requêtes de modules fondées sur la liste l’omettent. Comparez la liste du loader avec les mappings kernel exécutables, les pool tags, les objets device/driver, les service keys, les adresses de callbacks et les pointeurs de dispatch qui aboutissent en dehors d’une image listée.<sup>[[1]](#references)</sup>

## Protection et camouflage fondés sur des callbacks

Un rootkit peut combiner des frameworks de callbacks documentés avec DKOM et des hooks :<sup>[[1]](#references)</sup>

- Les handlers de pré-opération de `ObRegisterCallbacks` pour `PsProcessType` et `PsThreadType` suppriment les droits utilisés pour la terminaison, l’accès à la VM, la duplication ou la manipulation de threads lorsqu’un appelant untrusted ouvre une cible protégée. Notez l’altitude du callback et résolvez chaque adresse de callback vers son module propriétaire.
- `PsSetCreateProcessNotifyRoutineEx` et `PsSetLoadImageNotifyRoutine` maintiennent l’état protected/ignored/hidden des processus à mesure que les processus et les images apparaissent ; un parcours ponctuel des processus peut compléter les objets qui existaient avant l’enregistrement.
- Un filesystem minifilter refuse l’accès aux chemins configurés. Une implémentation inhabituelle peut créer sa clé `Instances`, choisir une altitude dynamiquement et l’incrémenter/réessayer lorsque `FltRegisterFilter` signale une collision.
- Une routine `CmRegisterCallbackEx` peut supprimer les noms protégés de l’énumération et refuser les opérations directes d’ouverture, de renommage, de définition ou de suppression, tout en exemptant les trusted processes enregistrés.

Mettez en corrélation les enregistrements de `ObRegisterCallbacks`, les altitudes des registry callbacks, la sortie de `fltmc filters`, les clés de service `Instances` et les adresses de callbacks. Si les outils normaux sont filtrés, inspectez ces structures depuis une image mémoire offline ou une autre couche d’acquisition de confiance.<sup>[[1]](#references)</sup>

## Filtrage des résultats de Nsiproxy

Le camouflage réseau peut cibler `\Driver\Nsiproxy` : obtenir l’objet driver avec `ObReferenceObjectByName`, enregistrer un pointeur de handler, le remplacer par un wrapper et supprimer les enregistrements IPv4 renvoyés qui correspondent à une liste C2 gérée par IOCTL avant qu’ils n’atteignent le user mode. Les applications reposant sur les données NSI filtrées peuvent alors ne plus afficher la connexion, même si le trafic existe toujours.<sup>[[1]](#references)</sup>

Comparez les vues des connexions de l’hôte avec la capture de paquets, la télémétrie WFP/ETW et les objets réseau de la mémoire kernel. Inspectez également les pointeurs de dispatch/handler de `Nsiproxy` et vérifiez que chacun se résout à l’intérieur du module signé attendu ; un pointeur vers un mapping non listé peut relier le filtrage réseau au DKOM de `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Checklist d’investigation

Le signal le plus fort est le désaccord entre les couches, et non un seul nom de fichier ou hash. Mettez en corrélation :<sup>[[1]](#references)</sup>

1. La création d’un kernel service et un driver signé dont l’ancienneté du certificat, l’éditeur ou le chemin sont incohérents avec le produit installé.
2. La création du device, les liens DOS et le trafic IOCTL, y compris les noms de devices user mode et kernel qui ne correspondent pas.
3. Une requête d’enregistrement de PID suivie d’échecs, pour d’autres processus, lors de l’ouverture, de l’énumération, de la modification ou de la suppression des mêmes objets.
4. Les callbacks d’objets/registre/processus/images, les instances de minifilter et les hooks dont les adresses n’appartiennent pas à un driver normalement énuméré.
5. Les différences entre les inventaires de processus, modules, callbacks et réseau fondés sur des listes et ceux fondés sur des scans.

## References

- [1] [Kaspersky Securelist - HoneyMyte améliore CoolClient avec un Windows Kernel Rootkit signé](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
