# Acquisizione e montaggio delle immagini

{{#include ../../banners/hacktricks-training.md}}

## Acquisizione

> Acquisisci sempre in **sola lettura** e calcola l'**hash durante la copia**. Mantieni il dispositivo originale **protetto dalla scrittura** e lavora solo su copie verificate.

Registra marca, modello, numero di serie e capacità della sorgente, strumento e versione, timestamp, operatore, destinazione, errori e hash di acquisizione/verifica. Conserva un'immagine di archivio ed esamina una copia di lavoro separata.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` aggiunge al workflow di `dd` l’hashing al volo, la verifica dell’output, la registrazione degli errori e la suddivisione dell’output. `hof=` seleziona un output verificato tramite hash; `hash=`, `hlog=`, `log=` e `bufsz=` sono operandi separati.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager è un programma Linux grafico e multithread per creare immagini nei formati raw/dd, EWF e AFF legacy. **AFF e AFF4 sono formati diversi**; Guymager non dichiara di supportare l’output AFF4. Abilita SHA-256 e la verifica della destinazione nella finestra di acquisizione, quindi avvialo con `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

La specifica AFF4 v1.0 definisce un contenitore forense con storage virtualizzato, metadati arbitrari, compressione estensibile e hashing, oltre a un funzionamento ad alto throughput.<sup>[[1]](#references)</sup>

L’implementazione canonica in C/C++ usa `-i` per la sorgente e `-o` per il volume AFF4. Crea e conserva un hash esterno del contenitore come baseline di acquisizione.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

La documentazione attuale di FTK Imager indica la disponibilità di output raw/DD, E01 e AFF con verifica degli hash. Non etichettare il suo output AFF come AFF4.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### Strumenti EWF (libewf)

Per l’acquisizione non presidiata, la destinazione è `-t`, i metadati del caso si impostano con `-C/-D/-E/-e`, `-d sha256` aggiunge SHA-256 e `-l` registra gli errori di acquisizione e i digest. Verificare il set di segmenti completato prima dell’analisi.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Acquisizione di immagini dei dischi cloud

Uno snapshot del provider è una fonte di acquisizione in un preciso momento, non automaticamente un’immagine forense coerente a livello applicativo. Uno snapshot EBS esclude i dati ancora nella cache del guest; sospendi le scritture, metti l’applicazione in quiescenza, smonta il volume dati o arresta l’istanza di cui stai acquisendo il volume root, se il piano di risposta lo consente.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

Non descrivere gli snapshot EBS come file che possono essere semplicemente copiati in S3. Per ricostruire l’immagine a blocchi senza creare un volume, elenca i blocchi allocati con `ListSnapshotBlocks`, recupera ogni blocco da 512 KiB con `GetSnapshotBlock`, verifica il checksum restituito e riempi con zeri gli indici dei blocchi assenti dallo snapshot sparso.<sup>[[14]](#references)</sup>

Per Azure, crea lo snapshot, genera una SAS **di sola lettura** a breve scadenza, scarica il VHD, revoca l’accesso e calcola l’hash del risultato. Crea uno snapshot di ogni disco separatamente, a meno che il meccanismo di acquisizione non garantisca la coerenza coordinata.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Montaggio

### Considera le immagini come input ostile

Un filesystem malevolo può prendere di mira i parser delle partizioni e dei filesystem del kernel host. QEMU avverte esplicitamente di non collegare un'immagine guest non attendibile a NBD dell'host per montarla; libguestfs raccomanda di non montare mai direttamente un filesystem guest non attendibile con loop o `kpartx`.<sup>[[2]](#references)[[16]](#references)</sup>

Per un'immagine sconosciuta o controllata da un aggressore, preferisci `guestmount`. Analizza e monta il guest all'interno di una piccola appliance, quindi espone i file tramite FUSE. Forza il formato noto invece di affidarti al rilevamento automatico e mantieni l'appliance in sola lettura.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

Se dall'ispezione non è possibile dedurre il sistema operativo, sostituisci `-i` con un dispositivo guest esplicito, ad esempio `-m /dev/sda2`. I volumi LUKS cifrati possono essere specificati con selettori `--key`; evita di inserire una chiave direttamente nella cronologia della shell.<sup>[[17]](#references)</sup>

### Scelta del montaggio diretto sull'host

Usa il montaggio diretto sull'host solo per immagini attendibili o in una VM di analisi usa e getta:

1. Monta l'**intero disco** quando ti serve la tabella delle partizioni originale.
2. Monta l'immagine di una **singola partizione** quando ti serve un solo volume.
3. Collega l'immagine in sola lettura e specificane il formato. Monta anche il filesystem in sola lettura. `ro` da solo non impedisce il replay del journal di ext3/ext4, quindi usa `ro,noload` per i filesystem ext danneggiati.<sup>[[2]](#references)[[3]](#references)</sup>

`mmls` è utile quando la dimensione del settore non è di 512 byte o i metadati delle partizioni sono danneggiati; `-b` specifica la dimensione effettiva del settore del dispositivo. Continua qui l'analisi delle partizioni e dei filesystem:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Immagini raw (dd, estratte da AFF4)

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

Scollegare al termine:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

Per qcow2, VMDK o VHD/VHDX, determina il formato tramite una provenienza attendibile oppure esaminalo all'interno della VM di analisi usa e getta, quindi sostituisci `--format=raw` con il formato esplicito. Non affidarti mai al rilevamento automatico del formato lato host per input non attendibili.<sup>[[2]](#references)</sup>

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

Per i mount senza replay specifici del filesystem, ext3/ext4 usano `noload`, mentre XFS usa `norecovery` e richiede la modalità di sola lettura.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` può esporre una vista raw virtuale, ma questa contiene comunque la tabella delle partizioni originale. Usala con lo stesso flusso di lavoro basato su `mmls`, `guestmount` isolato o NBD in sola lettura, invece di montare il file dell’intero disco come filesystem.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### Volumi BitLocker

Usa la modalità di sola lettura su entrambi i livelli. `-u` senza valore richiede la password, evitando di inserirla negli argomenti del processo o nella cronologia della shell.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

Per LUKS o LVM, preferisci `guestmount -i --ro`: la sua appliance può esaminare layout comuni con volumi crittografati e volumi logici senza attivare sul host un gruppo di volumi non attendibile.<sup>[[17]](#references)</sup>

### Helper di kpartx

`kpartx` crea nodi device-mapper sul host e quindi non è adatto alle immagini non attendibili. Quando la mappatura diretta è giustificata, aggiungi `-r` per rendere le mappature delle partizioni di sola lettura e rimuovile passando lo stesso percorso dell’immagine usato per crearle.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Errori comuni di mount e relative soluzioni

| Errore | Causa tipica | Passaggio successivo sicuro |
|-------|---------------|----------------|
| `cannot mount ... read-only` | File system con journal non pulito | usare l'opzione specifica del file system per non riprodurre il journal, ad esempio `ro,noload` per ext4 |
| `bad superblock ...` | Partizione/offset del settore errato o file system danneggiato | verificare la dimensione e l'offset del settore con `mmls`; eseguire `fsck -n` solo su una copia verificata |
| `unknown filesystem type 'LVM2_member'` | La partizione selezionata è un volume fisico LVM | lasciare che libguestfs lo analizzi oppure isolare l'attivazione manuale di LVM in una VM usa e getta |

### Pulizia

Smontare i file system prima di scollegare i dispositivi sottostanti. Rimuovere anche il livello FUSE per EWF/xmount e tutte le mappature crypt o device-mapper create:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [Specifiche standard AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Documentazione di QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Pagina del manuale Linux mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Il file system SGI XFS (documentazione del kernel Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [Procedure consigliate SWGDE per la raccolta di prove digitali](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [Procedure consigliate SWGDE per l'acquisizione forense di computer](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [Pagina del manuale dc3dd(1)](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Homepage di Guymager e documentazione di configurazione](https://guymager.sourceforge.io/)
- [9] [Documentazione di c-aff4](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Formati e verifica di Exterro FTK Imager](https://www.exterro.com/digital-forensics-software)
- [11] [Manuale libewf ewfacquire(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [Manuale libewf ewfverify(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Creare snapshot Amazon EBS](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Leggere snapshot Amazon EBS con le API dirette di EBS](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Riferimento snapshot Azure CLI](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [Sicurezza di libguestfs](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
