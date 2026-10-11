# Erfassung und Einbindung von Images

{{#include ../../banners/hacktricks-training.md}}

## Erfassung

> Erfasse immer **schreibgeschützt** und **berechne während des Kopierens den Hash**. Halte das Originalgerät **schreibgeschützt** und arbeite ausschließlich mit verifizierten Kopien.

Dokumentiere Hersteller, Modell, Seriennummer und Größe der Quelle, Tool und Version, Zeitstempel, Bearbeiter, Ziel, Fehler sowie Erfassungs- und Verifizierungshashes. Bewahre ein Archiv-Image auf und untersuche eine separate Arbeitskopie.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` ergänzt den `dd`-Workflow um Hashing während der Verarbeitung, Ausgabeüberprüfung, Fehlerprotokollierung und aufgeteilte Ausgaben. `hof=` wählt eine hash-verifizierte Ausgabe aus; `hash=`, `hlog=`, `log=` und `bufsz=` sind separate Operanden.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager ist ein grafisches, multithreaded Linux-Imaging-Tool für die Ausgabeformate raw/dd, EWF und das ältere AFF. **AFF und AFF4 sind unterschiedliche Formate**; Guymager bietet keine AFF4-Ausgabe an. Aktiviere SHA-256 und die Überprüfung des Ziels im Akquisitionsdialog und starte das Tool anschließend mit `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

Die AFF4-v1.0-Spezifikation definiert einen forensischen Container mit virtualisiertem Speicher, beliebigen Metadaten, erweiterbarer Komprimierung und Hashing sowie hohem Datendurchsatz.<sup>[[1]](#references)</sup>

Die kanonische C/C++-Implementierung verwendet `-i` für die Quelle und `-o` für das AFF4-Volume. Erstelle einen externen Container-Hash und bewahre ihn als Ausgangsbasis für die Akquisition auf.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

Die aktuelle Dokumentation von FTK Imager nennt raw/DD-, E01- und AFF-Ausgabe mit Hash-Verifizierung. Die AFF-Ausgabe darf nicht als AFF4 bezeichnet werden.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### EWF-Tools (libewf)

Für eine unbeaufsichtigte Erfassung wird `-t` als Ziel verwendet, Fallmetadaten werden mit `-C/-D/-E/-e` angegeben, `-d sha256` fügt SHA-256 hinzu und `-l` protokolliert Erfassungsfehler und Prüfsummen. Überprüfen Sie den vollständigen Segmentsatz vor der Analyse.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Cloud-Datenträger abbilden

Ein Provider-Snapshot ist eine zeitpunktbezogene Erfassungsquelle und nicht automatisch ein anwendungskonsistentes forensisches Abbild. Ein EBS-Snapshot schließt Daten aus, die noch im Cache des Gastbetriebssystems liegen. Pausiere Schreibvorgänge, bringe die Anwendung in einen konsistenten Zustand, hänge das Datenvolume aus oder stoppe die Instanz, wenn ihr Root-Volume erfasst wird und der Reaktionsplan dies zulässt.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

Beschreibe EBS-Snapshots nicht als Dateien, die einfach nach S3 kopiert werden können. Um das Block-Image ohne Erstellung eines Volumes zu rekonstruieren, ermittle mit `ListSnapshotBlocks` die belegten Blöcke, rufe jeden 512-KiB-Block mit `GetSnapshotBlock` ab, überprüfe die zurückgegebene Prüfsumme und fülle Blockindizes, die im Sparse-Snapshot fehlen, mit Nullen auf.<sup>[[14]](#references)</sup>

Erstelle für Azure den Snapshot, stelle eine kurzlebige **schreibgeschützte** SAS aus, lade die VHD herunter, widerrufe den Zugriff und hashe das Ergebnis. Erstelle für jede Festplatte einen eigenen Snapshot, es sei denn, der Erfassungsmechanismus gewährleistet eine koordinierte Konsistenz.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Einbinden

### Images als nicht vertrauenswürdige Eingaben behandeln

Ein bösartiges Dateisystem kann die Partitions- und Dateisystemparser des Host-Kernels angreifen. QEMU warnt ausdrücklich davor, ein nicht vertrauenswürdiges Gast-Image zum Einbinden mit dem Host-NBD zu verbinden. libguestfs empfiehlt außerdem, ein nicht vertrauenswürdiges Gastdateisystem niemals direkt mit `loop` oder `kpartx` einzubinden.<sup>[[2]](#references)[[16]](#references)</sup>

Verwende für ein unbekanntes oder von Angreifern kontrolliertes Image bevorzugt `guestmount`. Dabei wird das Gastdateisystem in einer kleinen Appliance analysiert und eingebunden; anschließend werden die Dateien über FUSE bereitgestellt. Gib das bekannte Format an, statt es automatisch erkennen zu lassen, und stelle sicher, dass die Appliance nur lesenden Zugriff hat.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

Wenn sich das Betriebssystem durch die Inspektion nicht ermitteln lässt, ersetze `-i` durch ein explizites Gastgerät wie `-m /dev/sda2`. Verschlüsselte LUKS-Volumes können mit `--key`-Selektoren angegeben werden; vermeide es, einen Schlüssel direkt im Shell-Verlauf zu speichern.<sup>[[17]](#references)</sup>

### Ein direktes Mounten auf dem Host wählen

Verwende ein direktes Mounten auf dem Host nur für vertrauenswürdige Images oder in einer Wegwerf-Analyse-VM:

1. Mounten Sie die **gesamte Festplatte**, wenn Sie deren ursprüngliche Partitionstabelle benötigen.
2. Mounten Sie ein **Image einer einzelnen Partition**, wenn Sie nur ein Volume benötigen.
3. Binden Sie das Image schreibgeschützt ein und geben Sie das Image-Format explizit an. Mounten Sie auch das Dateisystem schreibgeschützt. `ro` allein verhindert keine Journal-Wiedergabe bei ext3/ext4; verwenden Sie daher `ro,noload` für nicht ordnungsgemäß ausgehängte ext-Dateisysteme.<sup>[[2]](#references)[[3]](#references)</sup>

`mmls` ist hilfreich, wenn die Sektorgröße nicht 512 Byte beträgt oder Partitionsmetadaten beschädigt sind; `-b` gibt die tatsächliche Gerätesektorgröße an. Fahren Sie hier mit der Analyse von Partitionen und Dateisystemen fort:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Raw-Images (dd, aus AFF4 extrahiert)

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

Nach Abschluss aushängen:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

Bei qcow2, VMDK oder VHD/VHDX solltest du das Format anhand einer vertrauenswürdigen Herkunft feststellen oder in der Wegwerf-Analyse-VM prüfen und dann `--format=raw` durch das explizite Format ersetzen. Verlasse dich bei nicht vertrauenswürdigen Eingaben niemals auf die automatische Formaterkennung auf dem Host.<sup>[[2]](#references)</sup>

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

Für dateisystemspezifische No-Replay-Einhängungen verwenden ext3/ext4 `noload`, während XFS `norecovery` verwendet und den schreibgeschützten Modus erfordert.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` kann eine virtuelle Rohansicht bereitstellen, aber diese enthält weiterhin die ursprüngliche Partitionstabelle. Leiten Sie sie in denselben `mmls`-, isolierten `guestmount`- oder schreibgeschützten NBD-Workflow ein, anstatt die Datei des gesamten Datenträgers als Dateisystem einzuhängen.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### BitLocker-Volumes

Verwende auf beiden Ebenen den schreibgeschützten Modus. Bei `-u` ohne Wert wird das Passwort abgefragt, sodass es nicht in Prozessargumenten oder im Shell-Verlauf landet.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

For LUKS oder LVM ist `guestmount -i --ro` vorzuziehen; die Appliance kann gängige verschlüsselte und Logical-Volume-Layouts untersuchen, ohne eine fremde Volume Group auf dem Host zu aktivieren.<sup>[[17]](#references)</sup>

### kpartx-Hilfsprogramme

`kpartx` erstellt Device-Mapper-Knoten auf dem Host und ist daher für nicht vertrauenswürdige Images ungeeignet. Wenn direktes Mapping gerechtfertigt ist, füge `-r` hinzu, damit die Partitionszuordnungen schreibgeschützt sind, und entferne die Zuordnungen, indem du denselben Image-Pfad angibst, mit dem sie erstellt wurden.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Häufige Mount-Fehler und ihre Behebung

| Fehler | Typische Ursache | Sicherer nächster Schritt |
|-------|---------------|----------------|
| `cannot mount ... read-only` | Beschädigtes journaled filesystem | Verwende eine dateisystemspezifische Option zum Überspringen der Journal-Wiedergabe, z. B. ext4 `ro,noload` |
| `bad superblock ...` | Falsche Partition/Sektorposition oder beschädigtes Dateisystem | Prüfe Sektorgröße und Offset mit `mmls`; führe `fsck -n` nur auf einer verifizierten Kopie aus |
| `unknown filesystem type 'LVM2_member'` | Die ausgewählte Partition ist ein physisches LVM-Volume | Lass libguestfs das Volume untersuchen oder beschränke die manuelle LVM-Aktivierung auf eine Wegwerf-VM |

### Bereinigen

Hänge Dateisysteme aus, bevor du die zugehörigen Datenträger trennst. Entferne außerdem die FUSE-Schicht für EWF/xmount sowie alle erstellten crypt- oder device-mapper-Zuordnungen:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [AFF4-Standardspezifikation (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd-Dokumentation](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Linux-Handbuchseite zu mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Das SGI-XFS-Dateisystem (Linux-Kernel-Dokumentation)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [SWGDE-Best Practices zur Erfassung digitaler Beweismittel](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [SWGDE-Best Practices für Computer-Forensik-Akquisitionen](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [Handbuchseite zu dc3dd(1)](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Guymager-Homepage und Konfigurationsdokumentation](https://guymager.sourceforge.io/)
- [9] [c-aff4-Dokumentation](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Exterro FTK Imager-Formate und -Verifizierung](https://www.exterro.com/digital-forensics-software)
- [11] [libewf-Handbuch zu ewfacquire(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [libewf-Handbuch zu ewfverify(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Amazon-EBS-Snapshots erstellen](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Amazon-EBS-Snapshots mit EBS Direct APIs lesen](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Azure-CLI-Referenz zu Snapshots](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [Sicherheit von libguestfs](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
