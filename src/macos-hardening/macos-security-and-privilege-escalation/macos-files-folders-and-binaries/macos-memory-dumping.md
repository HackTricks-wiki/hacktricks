# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Artefacts mémoire

### Fichiers swap

Les fichiers swap, comme `/private/var/vm/swapfile0`, servent de **cache lorsque la mémoire physique est pleine**. Lorsqu'il n'y a plus de place en mémoire physique, son contenu est transféré vers un fichier swap puis rechargé en mémoire physique au besoin. Plusieurs fichiers swap peuvent exister, avec des noms comme swapfile0, swapfile1, etc.

### Image d'hibernation

Le fichier situé à `/private/var/vm/sleepimage` est essentiel en mode **hibernation**. **Les données de la mémoire sont stockées dans ce fichier lorsque OS X hiberne**. Au réveil de l'ordinateur, le système récupère les données mémoire depuis ce fichier, permettant à l'utilisateur de reprendre là où il s'était arrêté.

Sur les systèmes macOS modernes, ce fichier est généralement chiffré pour des raisons de sécurité, rendant sa récupération difficile.

- Pour vérifier si le sleepimage est chiffré, on peut exécuter la commande `sysctl vm.swapusage`. Cela indiquera si le fichier est chiffré.

### Journaux de pression mémoire

Un autre fichier important lié à la mémoire sur les systèmes macOS est le **journal de pression mémoire**. Ces journaux se trouvent dans `/var/log` et contiennent des informations détaillées sur l'utilisation de la mémoire et les événements de pression mémoire. Ils peuvent être particulièrement utiles pour diagnostiquer des problèmes liés à la mémoire ou comprendre comment le système gère la mémoire au fil du temps.

## Dumping memory with osxpmem

In order to dump the memory in a MacOS machine you can use [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note** : Il s'agit désormais principalement d'un **flux de travail hérité**. `osxpmem` dépend du chargement d'une extension noyau (kext), le projet [Rekall](https://github.com/google/rekall) est archivé, la dernière release date de **2017**, et le binaire publié cible les **Intel Macs**. Sur les versions récentes de macOS, en particulier sur **Apple Silicon**, l'acquisition de la RAM complète basée sur kext est généralement bloquée par les restrictions modernes sur les extensions noyau, SIP et les exigences de signature de la plateforme. En pratique, sur les systèmes modernes, vous finirez plus souvent par effectuer un **process-scoped dump** plutôt qu'une image de la RAM complète.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Si vous rencontrez cette erreur : `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Vous pouvez la corriger en procédant comme suit :
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**D'autres erreurs** peuvent être corrigées en **autorisant le chargement du kext** dans "Security & Privacy --> General", il suffit de **l'autoriser**.

Vous pouvez également utiliser ce **oneliner** pour télécharger l'application, charger le kext et dump the memory:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live process dumping with LLDB

Pour les **versions récentes de macOS**, l'approche la plus pratique consiste généralement à dump la mémoire d'un **processus spécifique** plutôt que d'essayer de créer une image de toute la mémoire physique.

LLDB peut sauvegarder un Mach-O core file depuis une cible en cours d'exécution:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Par défaut, cela crée généralement un **skinny core**. Pour forcer LLDB à inclure toute la mémoire mappée du processus :
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Commandes de suivi utiles avant dumping :
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Ceci suffit généralement lorsque l'objectif est de récupérer :

- Blobs de configuration décryptés
- Tokens, cookies ou identifiants en mémoire
- Secrets en clair protégés uniquement au repos
- Pages Mach-O décryptées après unpacking / JIT / runtime patching

Si la cible est protégée par le **hardened runtime**, ou si `taskgated` refuse l'attachement, vous aurez généralement besoin de l'une des conditions suivantes :

- La cible possède **`get-task-allow`**
- Votre debugger est signé avec le **debugger entitlement** approprié
- Vous êtes **root** et la cible est un processus tiers non protégé par le **hardened runtime**

Pour plus de contexte sur l'obtention d'un task port et ce qu'il est possible d'en faire :

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Dumps sélectifs avec Frida ou userland readers

Quand un full core est trop bruyant, dumper uniquement les **interesting readable ranges** est souvent plus rapide. Frida est particulièrement utile car il fonctionne bien pour la **targeted extraction** une fois que vous pouvez vous attacher au processus.

Approche exemple :

1. Énumérer les plages lisibles/écrivables
2. Filtrer par module, heap, stack, ou mémoire anonyme
3. Dumper seulement les régions contenant des chaînes candidates, clés, protobufs, plist/XML blobs, ou code/données décryptés

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
Ceci est utile lorsque vous voulez éviter des fichiers core gigantesques et ne collecter que :

- Segments du heap de l'application contenant des secrets
- Régions anonymes créées par des packers ou loaders personnalisés
- Pages de code JIT / unpacked après modification des protections

Des outils userland plus anciens comme [`readmem`](https://github.com/gdbinit/readmem) existent aussi, mais ils sont surtout utiles comme **références de code source** pour des dumps directs de type `task_for_pid`/`vm_read` et ne sont pas bien maintenus pour les workflows modernes Apple Silicon.

## Notes de triage rapide

- `sysctl vm.swapusage` reste un moyen rapide de vérifier **l'utilisation du swap** et si le swap est **chiffré**.
- `sleepimage` reste pertinent principalement pour les scénarios de **hibernate/safe sleep**, mais les systèmes modernes le protègent souvent ; il doit donc être considéré comme une **source d'artefacts à vérifier**, et non comme une voie d'acquisition fiable.
- Sur les versions récentes de macOS, le **dumping au niveau processus** est généralement plus réaliste que l'**imagerie complète de la mémoire physique**, à moins que vous ne contrôliez la politique de boot, l'état de SIP et le chargement des kexts.

## Références

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
