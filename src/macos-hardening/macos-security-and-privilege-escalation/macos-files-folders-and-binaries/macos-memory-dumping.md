# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Les swap files, comme `/private/var/vm/swapfile0`, servent de **caches lorsque la mémoire physique est pleine**. Lorsqu'il n'y a plus d'espace en mémoire physique, ses données sont transférées vers un swap file puis ramenées en mémoire physique selon les besoins. Plusieurs swap files peuvent être présents, avec des noms comme swapfile0, swapfile1, et ainsi de suite.

### Hibernate Image

Le fichier situé à `/private/var/vm/sleepimage` est crucial pendant le **mode hibernation**. **Les données de la mémoire sont stockées dans ce fichier lorsque OS X hiberne**. Lors du réveil de l'ordinateur, le système récupère les données mémoire depuis ce fichier, permettant à l'utilisateur de reprendre là où il s'était arrêté.

Il est important de noter que sur les systèmes MacOS modernes, ce fichier est généralement chiffré pour des raisons de sécurité, ce qui rend la récupération difficile.

- Pour vérifier si le chiffrement est activé pour le sleepimage, la commande `sysctl vm.swapusage` peut être exécutée. Cela montrera si le fichier est chiffré.

### Memory Pressure Logs

Un autre fichier important lié à la mémoire dans les systèmes MacOS est le **memory pressure log**. Ces logs se trouvent dans `/var/log` et contiennent des informations détaillées sur l'utilisation de la mémoire du système et les événements de pression mémoire. Ils peuvent être particulièrement utiles pour diagnostiquer des problèmes liés à la mémoire ou comprendre comment le système gère la mémoire au fil du temps.

## Dumping memory with osxpmem

Afin de dumper la mémoire sur une machine MacOS, vous pouvez utiliser [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: Il s'agit surtout d'un **legacy workflow** désormais. `osxpmem` dépend du chargement d'une extension du noyau, le projet [Rekall](https://github.com/google/rekall) est archivé, la dernière release date de **2017**, et le binaire publié cible les **Intel Macs**. Sur les versions actuelles de macOS, en particulier sur **Apple Silicon**, l'acquisition complète de la RAM via kext est généralement bloquée par les restrictions modernes sur les kernel extensions, SIP, et les exigences de signature de la plateforme. En pratique, sur les systèmes modernes, vous finirez plus souvent par faire un **process-scoped dump** à la place d'une image complète de la RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Si vous trouvez cette erreur : `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Vous pouvez la corriger en faisant :
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**D’autres erreurs** peuvent être corrigées en **autorisant le chargement du kext** dans "Security & Privacy --> General", il suffit de **l’autoriser**.

Vous pouvez aussi utiliser cette **commande en une ligne** pour télécharger l’application, charger le kext et dumper la mémoire :
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dump de processus en direct avec LLDB

Pour les **versions récentes de macOS**, l’approche la plus pratique consiste généralement à dumper la mémoire d’un **processus spécifique** au lieu d’essayer d’imager toute la mémoire physique.

LLDB peut enregistrer un fichier core Mach-O à partir d’une cible en cours d’exécution :
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
Ceci est généralement suffisant lorsque l’objectif est de récupérer :

- Des blobs de configuration déchiffrés
- Des tokens, cookies ou credentials en mémoire
- Des secrets en clair qui ne sont protégés qu’au repos
- Des pages Mach-O déchiffrées après unpacking / JIT / runtime patching

Si la cible est protégée par le **hardened runtime**, ou si `taskgated` refuse l’attachement, vous avez généralement besoin d’une de ces conditions :

- La cible possède **`get-task-allow`**
- Votre debugger est signé avec le bon **debugger entitlement**
- Vous êtes **root** et la cible est un processus tiers non-hardened

Pour plus de contexte sur l’obtention d’un task port et ce qu’il permet de faire :

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

Avant de perdre du temps avec LLDB/Frida, vérifiez rapidement si la cible est réellement **dumpable** :
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Sur le plan opérationnel, cela signifie généralement :

- Une application tierce livrée avec **`get-task-allow`** est souvent directement dumpable avec LLDB, et le dump الناتant peut exposer des données protégées par TCC auxquelles l’application a déjà accédé.
- Une cible **hardened** sans `get-task-allow` refusera souvent les attaches, même en tant que `root`, sauf si vous contrôlez les entitlements du debugger / le chemin de policy pertinent.
- Les processus tiers non hardened restent l’endroit le plus simple pour utiliser `lldb`, `vmmap`, Frida, ou des lecteurs personnalisés `task_for_pid`/`vm_read`.

## Selective dumps avec Frida ou des lecteurs userland

Quand un core complet est trop bruyant, dumper uniquement les **plages lisibles intéressantes** est souvent plus rapide. Frida est particulièrement utile car il fonctionne bien pour une **extraction ciblée** une fois que vous pouvez attacher au processus.

Approche d’exemple :

1. Énumérer les plages lisibles/inscriptibles
2. Filtrer par module, heap, stack, ou mémoire anonyme
3. Dumper uniquement les régions qui contiennent des chaînes candidates, clés, protobufs, blobs plist/XML, ou du code/données déchiffrés

Exemple Frida minimal pour dumper toutes les plages anonymes lisibles :
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
Ceci est utile lorsque vous voulez éviter de gigantesques fichiers core et ne collecter que :

- Des chunks du heap de l’app contenant des secrets
- Des régions anonymes créées par des packers ou loaders personnalisés
- Des pages de code JIT / unpacked après modification des protections

D’anciens outils userland comme [`readmem`](https://github.com/gdbinit/readmem) existent aussi, mais ils sont surtout utiles comme **références de source** pour du dumping direct de style `task_for_pid`/`vm_read` et ne sont pas bien maintenus pour les workflows Apple Silicon modernes.

## Snapshots du heap / VM avec `.memgraph`

Si vous vous intéressez surtout aux **heap objects**, à la **provenance des allocations**, ou à un snapshot pouvant être déplacé sur une autre machine, un `.memgraph` est souvent plus pratique qu’un énorme core Mach-O. L’outillage `leaks` peut en générer un à partir d’un processus en cours d’exécution :
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Puis triez-le hors ligne avec les outils Apple standard :
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` est la principale raison de conserver une capture `-fullContent`, car les étiquettes décrivant le contenu mémoire sont omises d’un `.memgraph` minimal.

C’est particulièrement utile lorsque :

- Vous voulez un **instantané plus petit et partageable** plutôt qu’un core complet
- `MallocStackLogging` était activé et vous voulez des **backtraces d’allocation**
- Vous connaissez déjà une **adresse heap intéressante** et voulez pivoter avec `malloc_history`
- Vous avez besoin d’un **aperçu rapide de la répartition VM/heap** avant de décider si un dump complet vaut le bruit généré

## Cibles fortement orientées Swift : `swift-inspect`

Pour les applications qui conservent des données de grande valeur dans des **objets runtime Swift**, `swift-inspect` peut être un bon complément à LLDB ou Frida. Au lieu de tout dumper d’abord, vous pouvez interroger des structures runtime Swift spécifiques depuis un processus en cours d’exécution :
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
This is handy to identify:

- Grandes tableaux Swift qui tamponnent des données intéressantes
- Des allocations de métadonnées qui révèlent les types chargés au runtime
- L’état de concurrence Swift (`Task`, actor, thread relationships) avant de faire un dump plus ciblé

For more object-level runtime triage once you can already inspect the process, check [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Quick triage notes

- `sysctl vm.swapusage` reste un moyen rapide de vérifier **l’utilisation du swap** et si le swap est **chiffré**.
- `sleepimage` reste surtout pertinent pour les scénarios de **hibernate/safe sleep**, mais les systèmes modernes le protègent généralement, donc il doit être considéré comme une **source d’artefacts à vérifier**, et non comme une voie d’acquisition fiable.
- Sur les versions récentes de macOS, le **process-level dumping** est généralement plus réaliste que le **full physical memory imaging** sauf si vous contrôlez la boot policy, l’état de SIP et le chargement des kexts.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
