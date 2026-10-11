# Beeldverkryging en montering

{{#include ../../banners/hacktricks-training.md}}

## Verkryging

> Verkry altyd data **slegs-lees** en **bereken die hash terwyl jy kopieer**. Hou die oorspronklike toestel **write-blocked** en werk slegs met geverifieerde kopieë.

Teken die bron se vervaardiger, model, reeksnommer en grootte aan, asook die nutsmiddel en weergawe, tydstempels, operateur, bestemming, foute en verkrygings-/verifikasiehashes. Bewaar ’n argiefbeeld en ondersoek ’n afsonderlike werkkopie.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` voeg hashing onderweg, uitvoerverifikasie, foutregistrasie en verdeelde uitvoer by die `dd`-werkvloei. `hof=` kies ’n hash-geverifieerde uitvoer; `hash=`, `hlog=`, `log=` en `bufsz=` is afsonderlike operande.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager is ’n grafiese, multithreaded Linux-imager vir raw/dd-, EWF- en verouderde AFF-uitvoer. **AFF en AFF4 is verskillende formate**; Guymager adverteer nie AFF4-uitvoer nie. Aktiveer SHA-256 plus bestemmingsverifikasie in die verkrygingsdialoog en begin dit dan met `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

Die AFF4 v1.0-spesifikasie definieer ’n forensiese houer met gevirtualiseerde berging, arbitrêre metadata, uitbreidbare kompressie en hashing, en hoë deurset.<sup>[[1]](#references)</sup>

Die kanonieke C/C++-implementering gebruik `-i` vir die bron en `-o` vir die AFF4-volume. Skep en behou ’n eksterne houerhash as die verkrygingsbasislyn.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

Die huidige FTK Imager-dokumentasie lys raw/DD, E01 en AFF as uitvoerformate met hashverifikasie. Moenie die AFF-uitvoer daarvan as AFF4 benoem nie.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### EWF tools (libewf)

Vir verkryging sonder toesig is die teiken `-t`, saakmetadata gebruik `-C/-D/-E/-e`, `-d sha256` voeg SHA-256 by, en `-l` teken verkrygingsfoute en digeste aan. Verifieer die voltooide segmentstel voordat jy dit ontleed.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Afneming van wolkskywe

’n Verskaffer-snapshot is ’n punt-in-tyd-insamelingsbron, nie outomaties ’n toepassingskonsekwente forensiese beeld nie. ’n EBS-snapshot sluit data uit wat steeds deur die gas-bedryfstelsel gekas word; staak skryfbewerkings, bring die toepassing tot ’n konsekwente toestand, ontkoppel die datavolume, of stop ’n instansie waarvan die wortelvolume vasgelê word wanneer die reaksieplan dit toelaat.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

Moenie EBS-snapshots beskryf as lêers wat eenvoudig na S3 gekopieer kan word nie. Om die blokbeeld te rekonstrueer sonder om ’n volume te skep, lys toegewysde blokke met `ListSnapshotBlocks`, haal elke 512 KiB-blok met `GetSnapshotBlock` op, valideer die teruggekeerde kontrolesom en vul ontbrekende blokindekse in die yl snapshot met nulle.<sup>[[14]](#references)</sup>

Skep vir Azure die snapshot, reik ’n kortlewende **read-only** SAS uit, laai die VHD af, herroep toegang en bereken ’n hash van die resultaat. Neem ’n snapshot van elke skyf afsonderlik, tensy die versamelingsmeganisme gekoördineerde konsekwentheid bied.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Monteer

### Behandel beelde as kwaadwillige invoer

’n Kwaadwillige lêerstelsel kan die partisies en lêerstelselontleders van die gasheerkern teiken. QEMU waarsku uitdruklik daarteen om ’n onbetroubare gastbeeld aan die gasheer se NBD te koppel om dit te monteer, en libguestfs beveel aan dat ’n onbetroubare gaslêerstelsel nooit direk met loop of `kpartx` gemonteer word nie.<sup>[[2]](#references)[[16]](#references)</sup>

Gebruik eerder `guestmount` vir ’n onbekende of aanvallergestuurde beeld. Dit ontleed en monteer die gas binne ’n klein toestel en stel dan lêers deur FUSE beskikbaar. Dwing die bekende formaat af in plaas daarvan om outomaties op te spoor, en hou die toestel se kant leesalleen.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

As inspeksie nie die bedryfstelsel kan aflei nie, vervang `-i` met ’n eksplisiete gastetoestel soos `-m /dev/sda2`. Geënkripteerde LUKS-volumes kan met `--key`-selektors verskaf word; vermy dit om ’n sleutel direk in die shell-geskiedenis te plaas.<sup>[[17]](#references)</sup>

### Kies ’n direkte host-mount

Gebruik ’n direkte host-mount slegs vir vertroude beelde of in ’n weggooibare analise-VM:

1. Mount die **hele skyf** wanneer jy die oorspronklike partisietabel nodig het.
2. Mount ’n **enkele partisiebeeld** wanneer jy net een volume nodig het.
3. Maak die koppeling leesalleen en dwing die beeldformaat af. Mount die lêerstelsel ook leesalleen. `ro` alleen keer nie dat ext3/ext4 joernaalherhaling plaasvind nie, dus gebruik `ro,noload` vir vuil ext-lêerstelsels.<sup>[[2]](#references)[[3]](#references)</sup>

`mmls` is nuttig wanneer die sektorgrootte nie 512 grepe is nie of partisienetadata beskadig is; `-b` verskaf die werklike toestelsektorgrootte. Gaan hier voort met partisie- en lêerstelselontleding:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Rou beelde (dd, uit AFF4 onttrek)

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

Ontkoppel wanneer jy klaar is:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

Vir qcow2, VMDK of VHD/VHDX, bepaal die formaat aan die hand van betroubare herkoms of inspekteer dit binne die weggooibare ontledings-VM, en vervang dan `--format=raw` met die uitdruklike formaat. Moet nooit vir onbetroubare invoer op outomatiese formaatherkenning aan die gasheerkant staatmaak nie.<sup>[[2]](#references)</sup>

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

Vir lêerstelselspesifieke mounts wat herhaling voorkom, gebruik ext3/ext4 `noload`, terwyl XFS `norecovery` gebruik en leesalleenmodus vereis.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` kan ’n virtuele raw-aansig blootstel, maar daardie aansig bevat steeds die oorspronklike partisietabel. Voer dit eerder deur dieselfde `mmls`-, geïsoleerde `guestmount`- of leesalleen-NBD-werkvloei as om die hele-skyflêer as ’n lêerstelsel te mount.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### BitLocker-volumes

Gebruik leesalleenmodus op albei lae. `-u` sonder ’n waarde vra vir die wagwoord, wat voorkom dat dit in prosesargumente of dopgeskiedenis geplaas word.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

Vir LUKS of LVM, verkies `guestmount -i --ro`; die appliance kan algemene geënkripteerde en logiese-volum uitleg inspekteer sonder om ’n vreemde volume group op die host te aktiveer.<sup>[[17]](#references)</sup>

### kpartx-hulpmiddels

`kpartx` skep host device-mapper-nodes en is dus nie geskik vir vyandige images nie. Wanneer direkte mapping geregverdig is, voeg `-r` by sodat die partition mappings leesalleen is, en verwyder mappings deur dieselfde image-pad te gebruik waarmee hulle geskep is.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Algemene mount-foute en oplossings

| Fout | Tipiese oorsaak | Veilige volgende stap |
|-------|---------------|----------------|
| `cannot mount ... read-only` | Vuil gejoernaleerde lêerstelsel | gebruik die lêerstelselspesifieke no-replay-opsie, soos ext4 `ro,noload` |
| `bad superblock ...` | Verkeerde partisie-/sektorverskuiwing of beskadigde lêerstelsel | bevestig sektor-grootte en verskuiwing met `mmls`; voer `fsck -n` slegs op ’n geverifieerde kopie uit |
| `unknown filesystem type 'LVM2_member'` | Die gekose partisie is ’n LVM-fisiese volume | laat libguestfs dit inspekteer, of isoleer handmatige LVM-aktivering in ’n weggooibare VM |

### Opruiming

Ontkoppel lêerstelsels voordat jy hul onderliggende toestelle ontkoppel. Verwyder ook die FUSE-laag vir EWF/xmount en enige crypt- of device-mapper-karterings wat geskep is:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [AFF4 Standard-spesifikasie (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd-dokumentasie](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [mount(8) Linux-manbladsy](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Die SGI XFS-lêerstelsel (Linux-kerneldokumentasie)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [SWGDE se beste praktyke vir die insameling van digitale bewyse](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [SWGDE se beste praktyke vir rekenaarforensiese verkrygings](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [dc3dd(1)-manbladsy](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Guymager-tuisblad en konfigurasiedokumentasie](https://guymager.sourceforge.io/)
- [9] [c-aff4-dokumentasie](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Exterro FTK Imager-formate en verifikasie](https://www.exterro.com/digital-forensics-software)
- [11] [libewf ewfacquire(1)-handleiding](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [libewf ewfverify(1)-handleiding](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Skep Amazon EBS-snapshots](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Lees Amazon EBS-snapshots met EBS direct API's](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Azure CLI-snapshotverwysing](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [libguestfs-sekuriteit](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
