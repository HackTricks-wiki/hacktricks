# Dump mémoire de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Artefacts mémoire

### Fichiers d’échange

Les fichiers d’échange, tels que `/private/var/vm/swapfile0`, servent de **caches lorsque la mémoire physique est pleine**. Lorsqu’il n’y a plus de place dans la mémoire physique, ses données sont transférées vers un fichier d’échange, puis réintégrées dans la mémoire physique selon les besoins. Plusieurs fichiers d’échange peuvent être présents, avec des noms tels que swapfile0, swapfile1, etc.

### Image d’hibernation

Le fichier situé à `/private/var/vm/sleepimage` est essentiel lors du **mode hibernation**. **Les données de la mémoire sont stockées dans ce fichier lorsque OS X hiberne**. Au réveil de l’ordinateur, le système récupère les données mémoire depuis ce fichier, permettant à l’utilisateur de reprendre là où il s’était arrêté.

Il convient de noter que sur les systèmes MacOS modernes, ce fichier est généralement chiffré pour des raisons de sécurité, ce qui rend sa récupération difficile.

- Pour vérifier si le chiffrement est activé pour la sleepimage, la commande `sysctl vm.swapusage` peut être exécutée. Elle indiquera si le fichier est chiffré.

### Journaux de pression mémoire

Un autre fichier important lié à la mémoire dans les systèmes MacOS est le **journal de pression mémoire**. Ces journaux se trouvent dans `/var/log` et contiennent des informations détaillées sur l’utilisation de la mémoire du système et les événements de pression mémoire. Ils peuvent être particulièrement utiles pour diagnostiquer les problèmes liés à la mémoire ou comprendre comment le système gère la mémoire au fil du temps.

## Dumping de la mémoire avec osxpmem

Pour dumper la mémoire d’une machine MacOS, vous pouvez utiliser [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Remarque** : Il s’agit désormais principalement d’un **workflow legacy**. `osxpmem` dépend du chargement d’une extension du kernel, le projet [Rekall](https://github.com/google/rekall) est archivé, la dernière release date de **2017**, et le binaire publié cible les **Mac Intel**. Sur les versions actuelles de macOS, en particulier sur **Apple Silicon**, l’acquisition complète de la RAM basée sur les kext est généralement bloquée par les restrictions modernes concernant les extensions du kernel, le SIP et les exigences de signature de la plateforme. En pratique, sur les systèmes modernes, vous effectuerez plus souvent un **dump limité à un processus** plutôt qu’une image de la RAM entière.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Si vous rencontrez cette erreur : `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)`, vous pouvez la corriger en procédant comme suit :
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**D'autres erreurs** peuvent être corrigées en **autorisant le chargement du kext** dans « Security & Privacy --> General », il suffit de **l'autoriser**.

Vous pouvez également utiliser cet **oneliner** pour télécharger l'application, charger le kext et dumper la mémoire :
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumping d'un processus live avec LLDB

Pour les **versions récentes de macOS**, l'approche la plus pratique consiste généralement à dumper la mémoire d'un **processus spécifique** plutôt qu'à tenter de créer une image de toute la mémoire physique.

LLDB peut enregistrer un fichier core Mach-O à partir d'une cible live :
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Par défaut, cela crée généralement un **skinny core**. Pour forcer LLDB à inclure toute la mémoire mappée du processus :
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Commandes de suivi utiles avant le dumping :
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Cela suffit généralement lorsque l’objectif est de récupérer :

- Des blobs de configuration déchiffrés
- Des tokens, cookies ou credentials présents en mémoire
- Des secrets en clair uniquement protégés au repos
- Des pages Mach-O déchiffrées après unpacking / JIT / runtime patching

Si la cible est protégée par le **hardened runtime**, ou si `taskgated` refuse l’attach, vous devez généralement remplir l’une des conditions suivantes :

- La cible possède **`get-task-allow`**
- Votre debugger est signé avec le **debugger entitlement** approprié
- Vous êtes **root** et la cible est un processus tiers non hardened

Pour plus d’informations sur l’obtention d’un task port et sur ce qu’il est possible d’en faire :

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Vérifications rapides avant l’attach

Avant de consacrer du temps à LLDB/Frida, vérifiez rapidement si la cible est réellement **dumpable** :
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
En pratique, cela signifie généralement :

- Une app tierce livrée avec **`get-task-allow`** peut souvent être directement dumpée avec LLDB, et le dump obtenu peut exposer des données protégées par TCC auxquelles l’app a déjà accédé.<sup>[[1]](#references)</sup>
- Une cible **hardened** sans `get-task-allow` rejettera généralement les attaches, même en tant que `root`, sauf si vous contrôlez les entitlements du debugger concernés ou le chemin de policy approprié.
- Les processus tiers non hardened restent l’endroit le plus simple pour utiliser `lldb`, `vmmap`, Frida ou des lecteurs personnalisés basés sur `task_for_pid`/`vm_read`.

### Rechercher les helpers imbriqués dumpables

Les recherches récentes sur les apps macOS notarized continuent de trouver **`get-task-allow` dans les helpers imbriqués**, plutôt que dans le binaire GUI principal. Lorsqu’une app de niveau supérieur semble hardened, énumérez ses **services XPC**, ses **login items**, ses **helper tools** et ses CLI incluses avant d’abandonner :
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Un exécutable imbriqué avec `get-task-allow` est souvent l'endroit le plus simple où s'attacher avec `lldb`, vider un core ou extraire la mémoire avec un client `task_for_pid` personnalisé, même lorsque l'application principale est mieux durcie.

## Dumps sélectifs avec Frida ou des lecteurs userland

Lorsqu'un core complet contient trop de bruit, vider uniquement les **plages lisibles intéressantes** est souvent plus rapide. Frida est particulièrement utile, car il fonctionne bien pour une **extraction ciblée** une fois que vous pouvez vous attacher au processus.

Approche minimale :

1. Énumérer les plages lisibles/inscriptibles
2. Filtrer par module, heap, stack ou mémoire anonyme
3. Vider uniquement les régions contenant des chaînes candidates, des clés, des protobufs, des blobs plist/XML ou du code/des données déchiffrés

Exemple Frida minimal pour vider toutes les plages anonymes lisibles :
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
C'est utile lorsque vous voulez éviter les fichiers core volumineux et ne collecter que :

- Les chunks du heap de l'application contenant des secrets
- Les régions anonymes créées par des packers ou loaders personnalisés
- Les pages de code JIT / unpacked après modification des protections

Lorsque la cible continue à **allouer / libérer** de la mémoire pendant le dump, préférez la primitive **`readVolatile()`** de Frida à **`readByteArray()`** pour les plages instables. Elle est plus lente, mais évite de tuer la cible si une page devient illisible au milieu de la lecture. Pour les acquisitions plus volumineuses, il peut également être plus propre de renvoyer les chunks en streaming avec `send(..., data)` et de les compresser côté controller, plutôt que de créer des milliers de petits fichiers dans la cible.

Des outils userland plus anciens tels que [`readmem`](https://github.com/gdbinit/readmem) existent également, mais ils sont principalement utiles comme **références de code source** pour le dumping direct de type `task_for_pid`/`vm_read` et ne sont pas bien maintenus pour les workflows modernes sur Apple Silicon.

## Snapshots du heap / de la VM avec `.memgraph`

Si vous vous intéressez principalement aux **objets du heap**, à la **provenance des allocations** ou à un snapshot pouvant être déplacé vers une autre machine, un fichier `.memgraph` est souvent plus pratique qu'un core Mach-O volumineux. Les outils `leaks` peuvent en générer un à partir d'un processus en cours d'exécution :<sup>[[2]](#references)</sup>
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Ensuite, effectuez son triage hors ligne avec les outils Apple standard :
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` est la principale raison de conserver une capture `-fullContent`, car les labels décrivant le contenu de la mémoire sont omis d'un `.memgraph` minimal.

Cela est particulièrement utile lorsque :

- Vous voulez un **snapshot plus petit et partageable** plutôt qu'un core complet
- `MallocStackLogging` était activé et que vous voulez les **allocation backtraces**
- Vous connaissez déjà une **adresse heap intéressante** et voulez pivoter avec `malloc_history`
- Vous avez besoin d'une **vue rapide de la VM/heap** avant de décider si un dump complet vaut le bruit généré

### Triage différentiel de memgraph

Si vous contrôlez la manière dont la cible démarre, activez la **journalisation historique des allocations** avant le lancement afin que les snapshots ultérieurs conservent des backtraces utiles des allocations/libérations :
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Ensuite, capturez des snapshots autour de l’action intéressante et faites un diff hors ligne :
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
Il s'agit d'une méthode pratique pour isoler les **objets post-authentication**, les **buffers `CFData` volumineux** ou les **régions de VM anonymes** qui n'apparaissent qu'après une étape de déchiffrement, de décompression ou de récupération de secrets.

## Cibles principalement basées sur Swift : `swift-inspect`

Pour les applications qui conservent des données de grande valeur dans des **objets du runtime Swift**, `swift-inspect` peut être un bon complément à LLDB ou Frida. Au lieu de tout dumper au préalable, vous pouvez interroger des structures spécifiques du runtime Swift à partir d'un processus en cours d'exécution :
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
C'est utile pour identifier :

- Les grands tableaux Swift mettant en mémoire tampon des données intéressantes
- Les allocations de métadonnées qui révèlent les types chargés à l'exécution
- L'état de la concurrence Swift (`Task`, les actors et les relations entre threads) avant d'effectuer un dump plus ciblé

Pour un triage au niveau des objets une fois que vous pouvez déjà inspecter le processus, consultez [la page dédiée aux objets en mémoire](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Notes de triage rapide

- `sysctl vm.swapusage` reste un moyen rapide de vérifier **l'utilisation du swap** et de déterminer si le swap est **chiffré**.
- `sleepimage` reste principalement pertinent dans les scénarios d'**hibernation/safe sleep**, mais les systèmes modernes le protègent couramment. Il doit donc être considéré comme une **source d'artefacts à vérifier**, et non comme une méthode d'acquisition fiable.
- Sur les versions récentes de macOS, le **dump au niveau du processus** est généralement plus réaliste qu'une **image complète de la mémoire physique**, sauf si vous contrôlez la politique de démarrage, l'état de SIP et le chargement des kext.

## Références

- [1] [Autoriser ou non get-task-allow : analyse de la sécurité de macOS](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [Page de manuel de leaks(1)](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
