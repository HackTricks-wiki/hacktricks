# Système de fichiers, inodes et récupération

{{#include ../../banners/hacktricks-training.md}}

L’abus des systèmes de fichiers consiste souvent à brouiller la relation entre un chemin visible et l’objet qui se trouve derrière.

Les images disque peuvent dissimuler un autre système de fichiers.<sup>[[1]](#references)</sup> Des montages inscriptibles peuvent être utilisés par des tâches privilégiées.

Les hardlinks peuvent exposer le même inode sous un nom différent.<sup>[[3]](#references)</sup> Les fichiers supprimés peuvent rester lisibles via un descripteur de fichier ouvert.<sup>[[5]](#references)[[6]](#references)</sup>

Cette page se concentre sur la technique, et non sur un lab ou une cible spécifique.

## Images disque et montages loop

Un fichier ordinaire peut contenir un système de fichiers complet ; une image disque peut donc exposer une deuxième arborescence de système de fichiers lorsqu’elle est montée.<sup>[[1]](#references)</sup>

Les images de sauvegarde, les périphériques bloc copiés, les artefacts de VM ou les blobs renommés peuvent donc contenir des identifiants, des scripts, des clés SSH, des fichiers de configuration ou des flags, même s’ils ne semblent pas utiles de l’extérieur.

Identifiez les images probables avec `file` pour classifier un fichier candidat, `blkid` pour rechercher les métadonnées reconnues du système de fichiers, et `strings -a` pour analyser l’ensemble du fichier à la recherche de séquences imprimables.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Lorsque le montage est autorisé, utilisez un montage loop avec `ro` afin que l’image soit attachée en lecture seule ; la commande `find` ci-dessous limite la profondeur d’inspection et le type de fichier.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Si le montage n’est pas disponible et que l’image est au format ext2/ext3/ext4, inspectez directement ses métadonnées avec `debugfs`.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Cette technique est utile, car elle transforme un fichier d’apparence normale en une seconde arborescence de système de fichiers.<sup>[[1]](#references)</sup> Considérez-la comme un moyen de récupérer des données cachées, et non comme une élévation de privilèges en soi.

## Writable Mount Abuse

Un montage accessible en écriture devient dangereux lorsqu’un contexte plus privilégié fait ensuite confiance à un élément qu’il contient. La question importante n’est pas seulement « puis-je écrire ici ? », mais aussi « qui lira, exécutera, importera ou chargera ensuite quelque chose depuis cet emplacement ? ».

Utilisez `findmnt` pour examiner les systèmes de fichiers montés et leurs options.<sup>[[9]](#references)</sup>

Trouvez les montages accessibles en écriture et les consommateurs suspects à l’aide des prédicats documentés de `find` relatifs aux permissions, au type et aux limites du système de fichiers, puis utilisez `grep` récursivement pour rechercher la configuration des composants susceptibles de les utiliser.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Schémas d’abus courants :

- Une tâche cron ou un service systemd exécute un script accessible en écriture depuis le mount.<sup>[[13]](#references)[[14]](#references)</sup>
- Un service privilégié charge des plugins, des fichiers de configuration, des templates ou des binaires auxiliaires depuis le mount.
- Un mount contient des fichiers SUID et permet leur modification, leur remplacement ou la manipulation du chemin.
- Un conteneur ou un chroot expose un chemin adossé à l’hôte qui est accessible en écriture depuis l’environnement restreint. Les mount namespaces fournissent des hiérarchies de mount distinctes, tandis que `chroot()` ne modifie que la résolution des noms de chemin et ne constitue pas un sandbox complet.<sup>[[15]](#references)[[16]](#references)</sup>

Schéma de validation générique utilisant les mêmes prédicats `find`.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Lors de la démonstration de l’impact dans un lab autorisé, gardez le payload observable et minimal, par exemple en écrivant la sortie de `id` dans un fichier temporaire.<sup>[[23]](#references)</sup> La technique fondamentale consiste en une exécution différée via un emplacement inscriptible de confiance.

## Inodes et confusion de chemin

Un inode est l’objet du système de fichiers ; un chemin est uniquement un nom qui pointe vers celui-ci. Les métadonnées du périphérique et de l’inode permettent de distinguer les objets entre les systèmes de fichiers, tandis que les compteurs de liens révèlent la présence de plusieurs hard links.<sup>[[3]](#references)</sup> La suppression d’un chemin ne signifie pas toujours que les données ont disparu tant qu’un processus a encore le fichier ouvert.<sup>[[5]](#references)</sup>

Les prédicats de `find` ci-dessous comparent l’identité des inodes, les compteurs de liens, les limites entre périphériques et les horodatages.<sup>[[4]](#references)</sup>

Comparez les fichiers par inode et par périphérique avec `ls -i` et les formats de métadonnées de `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Trouvez chaque chemin visible correspondant au même inode avec `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Recherchez directement par numéro d’inode avec `find -inum` lorsque vous ne disposez que des métadonnées.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Cette technique est utile lorsqu’un fichier apparaît sous un nom inattendu, lorsqu’une application valide un chemin mais en utilise un autre, ou lorsqu’un wrapper privilégié interagit avec un inode également accessible ailleurs.

## Hardlink Abuse

Les hardlinks créent plusieurs noms pour le même inode. Ils ne pointent pas vers un chemin cible comme le font les symlinks ; ce sont des noms équivalents pour le même objet fichier.<sup>[[3]](#references)</sup>

Trouvez les fichiers SUID avec plusieurs hardlinks à l’aide des prédicats de permissions et de nombre de liens de `find`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspectez un fichier suspect avec `stat` et `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Pourquoi c'est important :

- Un fichier sensible peut être accessible via un chemin moins évident.
- Un wrapper SUID peut être dissimulé derrière un nom qui ne semble pas privilégié.
- Un nettoyage qui supprime un pathname peut laisser un autre hardlink actif.

Le sysctl Linux `fs.protected_hardlinks` peut limiter la création de hardlinks entre différentes limites de privilèges.<sup>[[7]](#references)</sup> Les hardlinks existants doivent tout de même être examinés.

## Récupération de fichiers supprimés via des descripteurs ouverts

Lorsqu'un processus garde un fichier ouvert, la suppression de son dernier pathname laisse le fichier actif jusqu'à la fermeture du dernier descripteur ; Linux expose ces descripteurs sous `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Trouvez les fichiers supprimés mais ouverts en listant les descripteurs de `/proc` et en filtrant la sortie des fichiers ouverts.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
La récupération via ces liens dépend des permissions, car le déréférencement de `/proc/<pid>/fd` est soumis aux contrôles d'accès de ptrace et aux permissions des fichiers.<sup>[[6]](#references)</sup>

Lorsque cela est autorisé, `readlink` affiche la cible du descripteur et `cp` en copie le contenu.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Il s’agit d’une technique pratique pour récupérer des logs supprimés, des secrets temporaires, des binaires déposés, des fichiers ayant fait l’objet d’une rotation ou des scripts supprimés après leur exécution.

## Récupération ext avec debugfs

Sur les systèmes de fichiers ext2/ext3/ext4, `debugfs` peut examiner les métadonnées des inodes et extraire le contenu des inodes depuis un périphérique bloc ou une image ; sans `-w`, il ouvre le système de fichiers en lecture seule.<sup>[[2]](#references)</sup> Travaillez sur une copie ou une image en lecture seule chaque fois que possible.

Répertoriez les entrées et examinez les inodes avec des requêtes `debugfs` pour afficher le contenu des répertoires, l’état des inodes et vérifier la correspondance entre les inodes et les chemins.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Videz un inode connu avec la commande `debugfs dump`, puis identifiez le type de la sortie récupérée avec `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Cette récupération n’est pas garantie. Elle dépend de l’état du système de fichiers, de la réutilisation éventuelle des blocs et de la présence persistante des métadonnées. Pour ext3/ext4, le manuel de `debugfs` précise que la récupération d’inodes supprimés peut échouer, car les blocs de données des inodes libérés ne sont plus disponibles.<sup>[[2]](#references)</sup> Cette technique reste utile, car elle permet d’inspecter l’état au niveau des inodes sans dépendre du parcours normal des chemins.

## Épuisement et ordre des inodes

L’épuisement des inodes se produit lorsqu’un système de fichiers n’a plus de nœuds de fichiers disponibles, même s’il reste de l’espace disque libre.<sup>[[8]](#references)[[17]](#references)</sup> Cela provoque généralement des problèmes de fiabilité, mais peut également expliquer certains comportements étranges lors de la réponse à incident ou du triage en laboratoire.

Utilisez `df -i` pour afficher les informations sur les inodes plutôt que l’utilisation des blocs.<sup>[[8]](#references)</sup>

Vérifiez la pression exercée sur les inodes avec `df` et un comptage `find` des répertoires parents.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Les numéros d’inode et les horodatages peuvent également aider à reconstituer l’activité dans des environnements de laboratoire simples.

Les directives de format de `find` ci-dessous exposent ces champs.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Considérez l’ordre comme un indice, pas comme une preuve. Les opérations de copie, l’extraction d’archives, le type de système de fichiers, les restaurations et les écritures concurrentes peuvent toutes modifier les schémas d’allocation.

## Notes défensives

- Montez les images inconnues en lecture seule pendant l’analyse.<sup>[[1]](#references)</sup>
- Conservez les scripts privilégiés, les unités de service, les plugins et les chemins des helpers en dehors des montages accessibles en écriture par les utilisateurs.
- Utilisez `nosuid`, `nodev` et `noexec` lorsque cela est opérationnellement approprié ; ces options désactivent respectivement l’exécution set-ID/capability, l’interprétation des périphériques ou l’exécution directe de binaires sur le montage.<sup>[[1]](#references)</sup> Ne les considérez pas comme une boundary complète.
- Restreignez l’accès à `/proc/<pid>/fd` ; le déréférencement de ces liens est contrôlé par les vérifications d’accès ptrace et les permissions des fichiers.<sup>[[6]](#references)</sup> Restreignez autant que possible les métadonnées plus larges des processus et l’inspection inter-utilisateurs.
- Surveillez les points de montage accessibles en écriture, les hardlinks inattendus vers des fichiers privilégiés et les fichiers sensibles supprimés mais encore ouverts.

## References

- [1] [mount(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — page de manuel Linux](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — page de manuel Linux](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — page de manuel Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Documentation for /proc/sys/fs/ — Documentation du noyau Linux](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — page de manuel Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — page de manuel Linux](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — page de manuel Linux](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — page de manuel Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
