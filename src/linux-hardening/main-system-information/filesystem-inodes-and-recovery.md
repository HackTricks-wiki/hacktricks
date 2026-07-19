# Système de fichiers, inodes et récupération

{{#include ../../banners/hacktricks-training.md}}

L’abus du système de fichiers consiste souvent à brouiller la relation entre un chemin visible et l’objet qui se trouve derrière. Les images disque peuvent dissimuler un autre système de fichiers, les montages accessibles en écriture peuvent être utilisés par des tâches privilégiées, les hardlinks peuvent exposer le même inode sous un nom différent, et les fichiers supprimés peuvent rester lisibles via un descripteur de fichier ouvert.

Cette page se concentre sur la technique, et non sur un lab ou une cible spécifique.

## Images disque et montages Loop

Un fichier ordinaire peut contenir un système de fichiers complet. Les images de sauvegarde, les périphériques bloc copiés, les artefacts de VM ou les blobs renommés peuvent donc contenir des identifiants, des scripts, des clés SSH, des fichiers de configuration ou des flags, même s’ils ne semblent pas utiles de l’extérieur.

Identifiez les images probables :
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Si le montage est autorisé, montez d’abord les images inconnues en lecture seule :
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Si le montage n’est pas disponible, inspectez directement les métadonnées du système de fichiers :
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
La technique est utile, car elle transforme un fichier d’apparence normale en une seconde arborescence de système de fichiers. Considérez-la comme un moyen de récupérer des données cachées, et non comme une élévation de privilèges en soi.

## Writable Mount Abuse

Un point de montage accessible en écriture devient dangereux lorsqu’un contexte plus privilégié fait ensuite confiance à un élément qui s’y trouve. La question importante n’est pas seulement « puis-je écrire ici ? », mais aussi « qui lira, exécutera, importera ou chargera ensuite quelque chose depuis cet emplacement ? ».

Trouvez les points de montage accessibles en écriture et les consommateurs suspects :
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Schémas d’abus courants :

- Un cron ou une unité systemd privilégié(e) exécute un script accessible en écriture depuis le mount.
- Un service privilégié charge des plugins, des configurations, des templates ou des binaires auxiliaires depuis le mount.
- Un mount contient des fichiers SUID et permet leur modification, leur remplacement ou la manipulation de leur chemin.
- Un container ou un chroot expose un chemin adossé à l’hôte et accessible en écriture depuis l’environnement restreint.

Schéma générique de validation :
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Lors de la démonstration de l’impact dans un laboratoire autorisé, gardez le payload observable et minimal, par exemple en écrivant la sortie de `id` dans un fichier temporaire. La technique centrale consiste en une exécution différée via un emplacement inscriptible de confiance.

## Inodes et confusion de chemins

Un inode est l’objet du système de fichiers ; un chemin n’est qu’un nom qui y fait référence. Cela est important, car deux chemins différents peuvent pointer vers le même inode, et la suppression d’un nom de chemin ne signifie pas toujours que les données ont disparu.

Comparez les fichiers par inode et périphérique :
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Rechercher tous les chemins visibles correspondant au même inode :
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Recherchez directement par numéro d’inode lorsque vous ne disposez que des métadonnées :
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Cette technique est utile lorsqu’un fichier apparaît sous un nom inattendu, lorsqu’une application valide un chemin mais en utilise un autre, ou lorsqu’un wrapper privilégié interagit avec un inode également accessible ailleurs.

## Hardlink Abuse

Les hardlinks créent plusieurs noms pour le même inode. Ils ne pointent pas vers un chemin cible comme le font les symlinks ; ce sont des noms équivalents pour le même objet fichier.

Recherchez les fichiers SUID ayant plusieurs hardlinks :
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspecter un fichier suspect :
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Pourquoi c'est important :

- Un fichier sensible peut être accessible via un chemin moins évident.
- Un wrapper SUID peut être dissimulé derrière un nom qui ne semble pas privilégié.
- Une procédure de nettoyage qui supprime un chemin peut laisser un autre hardlink actif.

Les kernels modernes et les options de montage peuvent limiter la création de hardlinks afin de réduire ce type d'abus, mais les hardlinks existants méritent toujours d'être examinés.

## Récupération de fichiers supprimés via des FDs ouverts

Lorsqu'un processus maintient un fichier ouvert, les données du fichier peuvent rester accessibles même après la suppression du chemin. Linux expose ces descripteurs ouverts sous `/proc/<pid>/fd/`.

Trouver les fichiers ouverts supprimés :
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Récupérer les données lorsque les permissions le permettent :
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Cette technique pratique permet de récupérer des logs supprimés, des secrets temporaires, des binaires déposés, des fichiers en rotation ou des scripts supprimés après leur exécution.

## Récupération ext avec debugfs

Sur les systèmes de fichiers ext, `debugfs` peut inspecter les métadonnées des inodes et parfois dumper le contenu des fichiers depuis une image du système de fichiers. Travaillez sur une copie ou une image en lecture seule dans la mesure du possible.

Lister les entrées et inspecter les inodes :
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Extraire un inode connu :
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
La récupération n'est pas garantie. Elle dépend de l'état du système de fichiers, de la réutilisation éventuelle des blocs et de la persistance des métadonnées. Cette technique reste utile, car elle permet d'inspecter l'état au niveau des inodes sans dépendre du path traversal normal.

## Épuisement et ordre des inodes

L'épuisement des inodes se produit lorsqu'un système de fichiers n'a plus d'objets fichier disponibles, même s'il reste de l'espace disque libre. Cela entraîne généralement des problèmes de fiabilité, mais peut également expliquer des comportements étranges lors d'une réponse à incident ou d'un triage en laboratoire.

Vérifiez la pression exercée sur les inodes :
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Les numéros d’inode et les horodatages peuvent également aider à reconstituer l’activité dans des environnements de laboratoire simples :
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Traitez l’ordre comme un indice, et non comme une preuve. Les opérations de copie, l’extraction d’archives, le type de système de fichiers, les restaurations et les écritures concurrentes peuvent toutes modifier les schémas d’allocation.

## Notes défensives

- Montez les images inconnues en lecture seule pendant l’analyse.
- Conservez les scripts privilégiés, les unités de service, les plugins et les chemins des helpers en dehors des points de montage accessibles en écriture par les utilisateurs.
- Utilisez `nosuid`, `nodev` et `noexec` lorsque cela est approprié sur le plan opérationnel, mais ne les considérez pas comme une boundary complète.
- Restreignez autant que possible l’accès à `/proc/<pid>/fd`, aux métadonnées des processus et à l’inspection des processus d’autres utilisateurs.
- Surveillez les points de montage accessibles en écriture, les hardlinks inattendus vers des fichiers privilégiés et les fichiers sensibles supprimés mais encore ouverts.
{{#include ../../banners/hacktricks-training.md}}
