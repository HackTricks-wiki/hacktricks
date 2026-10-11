# Acquisition et montage d’image

{{#include ../../banners/hacktricks-training.md}}

## Acquisition

> Effectuez toujours l’acquisition en **lecture seule** et **calculez le hash pendant la copie**. Protégez l’appareil d’origine contre l’écriture et travaillez uniquement sur des copies vérifiées.

Consignez la marque, le modèle, le numéro de série et la taille de la source, l’outil et sa version, les horodatages, l’opérateur, la destination, les erreurs ainsi que les hash d’acquisition et de vérification. Conservez une image d’archive et examinez une copie de travail distincte.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` ajoute au flux de travail `dd` le hachage à la volée, la vérification des sorties, la journalisation des erreurs et le fractionnement des sorties. `hof=` sélectionne une sortie dont le hachage est vérifié ; `hash=`, `hlog=`, `log=` et `bufsz=` sont des opérandes distincts.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager est un outil d’imagerie Linux graphique et multithread pour les formats de sortie raw/dd, EWF et AFF historique. **AFF et AFF4 sont des formats différents** ; Guymager n’annonce pas la prise en charge du format AFF4 en sortie. Activez SHA-256 et la vérification de la destination dans la boîte de dialogue d’acquisition, puis lancez-le avec `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

La spécification AFF4 v1.0 définit un conteneur forensique avec stockage virtualisé, métadonnées arbitraires, compression et hachage extensibles, ainsi qu’un fonctionnement à haut débit.<sup>[[1]](#references)</sup>

L’implémentation C/C++ de référence utilise `-i` pour la source et `-o` pour le volume AFF4. Créez et conservez un hachage externe du conteneur comme référence d’acquisition.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

La documentation actuelle de FTK Imager mentionne les formats de sortie raw/DD, E01 et AFF, avec vérification des hashes. Ne présentez pas son format de sortie AFF comme étant AFF4.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### Outils EWF (libewf)

Pour une acquisition automatisée, la cible est `-t`, les métadonnées de dossier utilisent `-C/-D/-E/-e`, `-d sha256` ajoute SHA-256 et `-l` consigne les erreurs d’acquisition et les condensats. Vérifiez l’ensemble des segments une fois l’acquisition terminée, avant l’analyse.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Imagerie des disques cloud

Un snapshot fourni par un prestataire est une source de collecte à un instant donné, pas automatiquement une image forensique cohérente avec l’application. Un snapshot EBS exclut les données encore mises en cache par le système invité ; suspendez les écritures, mettez l’application au repos, démontez le volume de données ou arrêtez une instance dont le volume racine est capturé, si le plan d’intervention le permet.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

Ne présentez pas les snapshots EBS comme des fichiers qu’il suffit de copier vers S3. Pour reconstruire l’image disque sans créer de volume, énumérez les blocs alloués avec `ListSnapshotBlocks`, récupérez chaque bloc de 512 Kio avec `GetSnapshotBlock`, vérifiez la somme de contrôle renvoyée et remplissez de zéros les index de blocs absents du snapshot sparse.<sup>[[14]](#references)</sup>

Pour Azure, créez le snapshot, générez un SAS **en lecture seule** à courte durée de validité, téléchargez le VHD, révoquez l’accès et calculez le hash du résultat. Effectuez un snapshot de chaque disque séparément, sauf si le mécanisme de collecte garantit la cohérence coordonnée.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Mount

### Considérez les images comme des entrées malveillantes

Un système de fichiers malveillant peut cibler les analyseurs de partitions et de systèmes de fichiers du noyau hôte. QEMU déconseille explicitement de connecter une image invitée non fiable au NBD de l’hôte pour la monter, et libguestfs recommande de ne jamais monter directement un système de fichiers invité non fiable avec `loop` ou `kpartx`.<sup>[[2]](#references)[[16]](#references)</sup>

Pour une image inconnue ou contrôlée par un attaquant, préférez `guestmount`. Il analyse et monte le système de fichiers invité dans une petite appliance, puis expose les fichiers via FUSE. Forcez le format connu au lieu d’utiliser l’auto-détection et gardez le côté appliance en lecture seule.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

Si l’inspection ne permet pas d’identifier le système d’exploitation, remplacez `-i` par un périphérique invité explicite, tel que `-m /dev/sda2`. Les volumes LUKS chiffrés peuvent être fournis avec des sélecteurs `--key` ; évitez de saisir une clé directement dans l’historique du shell.<sup>[[17]](#references)</sup>

### Choisir un montage direct sur l’hôte

N’effectuez un montage direct sur l’hôte qu’avec des images fiables ou dans une VM d’analyse jetable :

1. Montez le **disque entier** si vous avez besoin de sa table de partitions d’origine.
2. Montez une **image de partition unique** si vous n’avez besoin que d’un seul volume.
3. Rendez le périphérique associé accessible en lecture seule et forcez le format de l’image. Montez également le système de fichiers en lecture seule. `ro` seul n’empêche pas la relecture du journal ext3/ext4 ; utilisez donc `ro,noload` pour les systèmes de fichiers ext modifiés.<sup>[[2]](#references)[[3]](#references)</sup>

`mmls` est utile lorsque la taille des secteurs n’est pas de 512 octets ou que les métadonnées de partition sont endommagées ; `-b` indique la taille réelle des secteurs du périphérique. Poursuivez l’analyse des partitions et des systèmes de fichiers ici :<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Images brutes (dd, extraites d’AFF4)

```bash
# Identify partitions without attaching the image
mmls -b 512 disk.img

# Attach a known raw image read-only and force its format
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 --read-only --format=raw disk.img
lsblk /dev/nbd0 -o NAME,SIZE,RO,TYPE,FSTYPE,LABEL,UUID

# Example ext4 partition: prevent journal replay
sudo mount -o ro,noload /dev/nbd0p2 /mnt/evidence
```

Démontez une fois terminé :

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

Pour qcow2, VMDK ou VHD/VHDX, déterminez le format à partir d'une provenance fiable ou inspectez-le dans la VM d'analyse jetable, puis remplacez `--format=raw` par le format explicite. Ne vous fiez jamais à la détection automatique du format côté hôte pour une entrée non fiable.<sup>[[2]](#references)</sup>

### EWF (E01/EWFX)

```bash
# Verify, then expose the embedded raw media stream
mkdir -p /mnt/ewf /mnt/evidence
ewfverify evidence.E01
ewfmount evidence.E01 /mnt/ewf

# ewf1 is raw media data; attach it explicitly as raw and read-only
sudo qemu-nbd --connect=/dev/nbd1 --read-only --format=raw /mnt/ewf/ewf1
# Example XFS partition
sudo mount -o ro,norecovery /dev/nbd1p1 /mnt/evidence
```

Pour les montages sans rejeu propres à chaque système de fichiers, ext3/ext4 utilisent `noload`, tandis que XFS utilise `norecovery` et exige le mode lecture seule.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` peut exposer une vue brute virtuelle, mais celle-ci contient toujours la table de partition d’origine. Faites-la passer par le même workflow `mmls`, `guestmount` isolé ou NBD en lecture seule, au lieu de monter le fichier du disque entier comme un système de fichiers.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### Volumes BitLocker

Utilisez le mode lecture seule aux deux niveaux. `-u` sans valeur demande le mot de passe, ce qui évite de l’inclure dans les arguments du processus ou l’historique du shell.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

Pour LUKS ou LVM, privilégiez `guestmount -i --ro` ; son appliance peut inspecter les configurations courantes chiffrées et utilisant des volumes logiques sans activer de groupe de volumes étranger sur l’hôte.<sup>[[17]](#references)</sup>

### Assistants `kpartx`

`kpartx` crée des nœuds device-mapper sur l’hôte et ne convient donc pas aux images malveillantes. Lorsqu’un mappage direct est justifié, ajoutez `-r` afin que les mappages de partitions soient en lecture seule, puis supprimez-les en transmettant le même chemin d’image que celui utilisé pour les créer.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Erreurs courantes de montage et correctifs

| Erreur | Cause typique | Étape suivante sans risque |
|-------|---------------|----------------|
| `cannot mount ... read-only` | Système de fichiers journalisé non propre | utiliser l’option spécifique au système de fichiers pour désactiver la relecture du journal, comme `ro,noload` pour ext4 |
| `bad superblock ...` | Mauvaise partition/position du secteur ou système de fichiers endommagé | vérifier la taille et la position du secteur avec `mmls` ; exécuter `fsck -n` uniquement sur une copie vérifiée |
| `unknown filesystem type 'LVM2_member'` | La partition sélectionnée est un volume physique LVM | laisser libguestfs l’inspecter ou isoler l’activation manuelle de LVM dans une VM jetable |

### Nettoyage

Démonter les systèmes de fichiers avant de déconnecter leurs périphériques sous-jacents. Supprimer également la couche FUSE pour EWF/xmount ainsi que tout mappage crypt ou device-mapper créé :

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [Spécification de la norme AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Documentation de QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Page de manuel Linux mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Le système de fichiers SGI XFS (documentation du noyau Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [Bonnes pratiques de SWGDE pour la collecte de preuves numériques](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [Bonnes pratiques de SWGDE pour les acquisitions en informatique légale](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [Page de manuel dc3dd(1)](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Site officiel de Guymager et documentation de configuration](https://guymager.sourceforge.io/)
- [9] [Documentation de c-aff4](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Formats et vérification d’Exterro FTK Imager](https://www.exterro.com/digital-forensics-software)
- [11] [Manuel libewf ewfacquire(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [Manuel libewf ewfverify(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Créer des snapshots Amazon EBS](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Lire des snapshots Amazon EBS avec les API directes EBS](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Référence des snapshots Azure CLI](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [Sécurité de libguestfs](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
