# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Les fichiers d'échange, tels que `/private/var/vm/swapfile0`, servent de **caches lorsque la mémoire physique est pleine**. Lorsqu'il n'y a plus de place dans la mémoire physique, ses données sont transférées vers un fichier d'échange et ensuite ramenées en mémoire physique au besoin. Plusieurs fichiers d'échange peuvent être présents, avec des noms comme swapfile0, swapfile1, et ainsi de suite.

### Hibernate Image

Le fichier situé à `/private/var/vm/sleepimage` est crucial pendant le **mode hibernation**. **Les données de la mémoire sont stockées dans ce fichier lorsque OS X hiberne**. Lors du réveil de l'ordinateur, le système récupère les données de la mémoire à partir de ce fichier, permettant à l'utilisateur de reprendre là où il s'était arrêté.

Il convient de noter que sur les systèmes MacOS modernes, ce fichier est généralement chiffré pour des raisons de sécurité, rendant la récupération difficile.

- Pour vérifier si le chiffrement est activé pour le sleepimage, la commande `sysctl vm.swapusage` peut être exécutée. Cela montrera si le fichier est chiffré.

### Memory Pressure Logs

Un autre fichier important lié à la mémoire dans les systèmes MacOS est le **journal de pression mémoire**. Ces journaux se trouvent dans `/var/log` et contiennent des informations détaillées sur l'utilisation de la mémoire du système et les événements de pression. Ils peuvent être particulièrement utiles pour diagnostiquer des problèmes liés à la mémoire ou comprendre comment le système gère la mémoire au fil du temps.

## Dumping memory with osxpmem

Pour dumper la mémoire sur une machine MacOS, vous pouvez utiliser [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note** : Les instructions suivantes ne fonctionneront que pour les Macs avec une architecture Intel. Cet outil est maintenant archivé et la dernière version a été publiée en 2017. Le binaire téléchargé en utilisant les instructions ci-dessous cible les puces Intel car Apple Silicon n'était pas disponible en 2017. Il peut être possible de compiler le binaire pour l'architecture arm64, mais vous devrez essayer par vous-même.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Si vous trouvez cette erreur : `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Vous pouvez le corriger en faisant :
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**D'autres erreurs** peuvent être corrigées en **permettant le chargement du kext** dans "Sécurité et confidentialité --> Général", il suffit de **permettre**.

Vous pouvez également utiliser cette **ligne de commande** pour télécharger l'application, charger le kext et dumper la mémoire :
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{{#include ../../../banners/hacktricks-training.md}}
