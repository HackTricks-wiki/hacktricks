# Upatikanaji na Uwekaji wa Picha

{{#include ../../banners/hacktricks-training.md}}

## Upatikanaji

> Pata data kila wakati kwa hali ya **read-only** na **kokotoa hash unapoinakili**. Zuia kifaa asili kisiandikwe kwa kutumia **write-blocker**, na ufanyie kazi nakala zilizothibitishwa pekee.

Rekodi mtengenezaji, modeli, nambari ya ufuatiliaji na ukubwa wa chanzo, zana na toleo lake, mihuri ya muda, mhudumu, mahali pa kuhifadhi, hitilafu na hash za upatikanaji/uthibitishaji. Hifadhi picha ya kumbukumbu na uchunguze nakala tofauti ya kufanyia kazi.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` huongeza hashing ya papo hapo, uthibitishaji wa matokeo, uwekaji wa kumbukumbu za hitilafu na matokeo yaliyogawanywa katika workflow ya `dd`. `hof=` huchagua matokeo yaliyothibitishwa kwa hash; `hash=`, `hlog=`, `log=` na `bufsz=` ni operands tofauti.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager ni zana ya Linux yenye kiolesura cha picha na uwezo wa kutumia nyuzi nyingi kwa ajili ya kutengeneza image katika miundo ya raw/dd, EWF na AFF ya zamani. **AFF na AFF4 ni miundo tofauti**; Guymager haitangazi uwezo wa kutoa AFF4. Washa SHA-256 pamoja na uthibitishaji wa lengwa kwenye kisanduku cha mazungumzo cha acquisition, kisha iwashe kwa kutumia `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

Vipimo vya AFF4 v1.0 vinafafanua kontena la uchunguzi wa kidijitali lenye hifadhi iliyoboreshwa, metadata ya aina yoyote, compression na hashing zinazoweza kupanuliwa, pamoja na utendaji wa kasi ya juu.<sup>[[1]](#references)</sup>

Utekelezaji rasmi wa C/C++ hutumia `-i` kwa chanzo na `-o` kwa volume ya AFF4. Unda na uhifadhi hash ya kontena la nje kama msingi wa acquisition.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

Nyaraka za sasa za FTK Imager zinataja kutoa faili za raw/DD, E01 na AFF pamoja na uthibitishaji wa hash. Usitaje matokeo yake ya AFF kama AFF4.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### Zana za EWF (libewf)

Kwa upataji bila uangalizi, target ni `-t`, metadata ya kesi hutumia `-C/-D/-E/-e`, `-d sha256` huongeza SHA-256, na `-l` huhifadhi hitilafu za upataji na digest. Thibitisha seti kamili ya segmenti kabla ya uchanganuzi.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Kuunda picha za diski za cloud

Snapshot ya provider ni chanzo cha kunasa hali ya wakati fulani, si picha ya forensic inayohakikisha kiotomatiki uthabiti wa application. Snapshot ya EBS haijumuishi data ambayo bado imehifadhiwa kwenye cache ya guest; sitisha writes, tuliza application, ondoa volume ya data, au simamisha instance ambayo root volume yake inanasa, ikiwa mpango wa response unaruhusu.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

Usieleze EBS snapshots kama faili zinazoweza kunakiliwa tu hadi S3. Ili kuunda upya picha ya block bila kuunda volume, orodhesha blocks zilizotengwa kwa kutumia `ListSnapshotBlocks`, pakua kila block ya 512 KiB kwa kutumia `GetSnapshotBlock`, hakiki checksum iliyorejeshwa na ujaze kwa zero faharasa za blocks ambazo hazipo kwenye sparse snapshot.<sup>[[14]](#references)</sup>

Kwa Azure, unda snapshot, toa SAS ya muda mfupi ya **kusoma tu**, pakua VHD, batilisha ufikiaji na ukokotoe hash ya matokeo. Tengeneza snapshot ya kila diski kivyake isipokuwa utaratibu wa ukusanyaji utoe consistency iliyoratibiwa.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Mount

### Chukulia images kama ingizo hasidi

Filesystem hasidi inaweza kulenga partition na filesystem parsers za kernel ya host. QEMU inaonya wazi dhidi ya kuunganisha guest image isiyoaminika kwenye NBD ya host kwa ajili ya mounting, na libguestfs inapendekeza kutowahi kumount filesystem ya guest isiyoaminika moja kwa moja kwa kutumia loop au `kpartx`.<sup>[[2]](#references)[[16]](#references)</sup>

Pendelea `guestmount` kwa image isiyojulikana au inayodhibitiwa na mshambuliaji. Huchanganua na kumount guest ndani ya appliance ndogo, kisha hufichua faili kupitia FUSE. Lazimisha format inayojulikana badala ya kutumia auto-detection, na hakikisha upande wa appliance uko read-only.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

Ikiwa ukaguzi hauwezi kubaini OS, badilisha `-i` kwa kifaa mahususi cha guest kama vile `-m /dev/sda2`. Volumes zilizosimbwa kwa LUKS zinaweza kutolewa kwa kutumia selectors za `--key`; epuka kuweka key moja kwa moja kwenye historia ya shell.<sup>[[17]](#references)</sup>

### Kuchagua mount ya moja kwa moja kwenye host

Tumia mount ya moja kwa moja kwenye host kwa images unazoziamini tu au kwenye VM ya uchanganuzi inayoweza kutupwa:

1. Mount **diski nzima** unapohitaji jedwali lake la awali la partitions.
2. Mount **image ya partition moja** unapohitaji volume moja tu.
3. Fanya attachment iwe ya kusoma tu na uweke wazi format ya image. Pia mount filesystem iwe ya kusoma tu. `ro` pekee haizuii ext3/ext4 kucheza tena journal, kwa hivyo tumia `ro,noload` kwa filesystems za ext zilizo dirty.<sup>[[2]](#references)[[3]](#references)</sup>

`mmls` ni muhimu wakati ukubwa wa sector si baiti 512 au metadata ya partition imeharibika; `-b` huweka ukubwa halisi wa sector wa kifaa. Endelea na uchanganuzi wa partitions na filesystems hapa:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Images ghafi (dd, zilizotolewa kutoka AFF4)

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

Ondoa muunganisho ukimaliza:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

Kwa qcow2, VMDK au VHD/VHDX, thibitisha umbizo kupitia chanzo kinachoaminika au ulikague ndani ya VM ya uchanganuzi inayoweza kutupwa, kisha badilisha `--format=raw` na umbizo husika lililotajwa wazi. Usiwahi kutegemea utambuzi wa umbizo kiotomatiki upande wa host kwa ingizo lisiloaminika.<sup>[[2]](#references)</sup>

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

Kwa mount zisizocheza tena (no-replay) zinazohusu filesystem maalum, ext3/ext4 hutumia `noload`, ilhali XFS hutumia `norecovery` na huhitaji hali ya read-only.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` inaweza kutoa mwonekano wa raw wa kielektroniki, lakini mwonekano huo bado una jedwali asili la partitions. Ipitishe kwenye mtiririko huohuo wa `mmls`, `guestmount` iliyotengwa au NBD ya read-only badala ya ku-mount faili ya diski nzima kama filesystem.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### Volumes za BitLocker

Tumia mode ya read-only kwenye tabaka zote mbili. `-u` bila thamani hukuomba nenosiri, hivyo huepusha kuliweka kwenye hoja za mchakato au historia ya shell.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

Kwa LUKS au LVM, tumia `guestmount -i --ro`; appliance yake inaweza kukagua mipangilio ya kawaida ya volume zilizofichwa na za kimantiki bila kuamilisha volume group isiyo ya mwenyeji kwenye host.<sup>[[17]](#references)</sup>

### Zana saidizi za kpartx

`kpartx` huunda nodi za host device-mapper, kwa hiyo haifai kwa image zisizoaminika. Ikiwa uchoraji ramani wa moja kwa moja unahitajika, ongeza `-r` ili partition mappings ziwe za kusoma pekee, na ondoa mappings kwa kupitisha njia ileile ya image iliyotumika kuziunda.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Makosa ya kawaida ya mount na marekebisho

| Hitilafu | Sababu ya kawaida | Hatua salama inayofuata |
|-------|---------------|----------------|
| `cannot mount ... read-only` | Mfumo wa faili wenye journal ulioharibika | tumia chaguo la kuzuia replay linalohusu mfumo huo wa faili, kama `ro,noload` ya ext4 |
| `bad superblock ...` | Partisheni/offset ya sekta isiyo sahihi au mfumo wa faili ulioharibika | thibitisha ukubwa wa sekta na offset kwa kutumia `mmls`; endesha `fsck -n` kwenye nakala iliyothibitishwa pekee |
| `unknown filesystem type 'LVM2_member'` | Partisheni iliyochaguliwa ni volume halisi ya LVM | ruhusu libguestfs ichunguze, au tenga uanzishaji wa LVM wa mkono ndani ya VM ya matumizi ya mara moja |

### Usafishaji

Ondoa mount za mifumo ya faili kabla ya kutenganisha vifaa vinavyoihifadhi. Pia ondoa safu ya FUSE ya EWF/xmount na ramani zozote za crypt au device-mapper zilizoundwa:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [Maelezo ya Kawaida ya AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Nyaraka za QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Ukurasa wa mwongozo wa Linux wa mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Mfumo wa faili wa SGI XFS (nyaraka za Linux kernel)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [Mbinu Bora za SWGDE za Ukusanyaji wa Ushahidi wa Kidijitali](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [Mbinu Bora za SWGDE za Upataji wa Ushahidi wa Kompyuta](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [Ukurasa wa mwongozo wa dc3dd(1)](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Tovuti kuu ya Guymager na nyaraka za usanidi](https://guymager.sourceforge.io/)
- [9] [Nyaraka za c-aff4](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Miundo na uthibitishaji wa Exterro FTK Imager](https://www.exterro.com/digital-forensics-software)
- [11] [Mwongozo wa libewf ewfacquire(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [Mwongozo wa libewf ewfverify(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Unda snapshots za Amazon EBS](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Soma snapshots za Amazon EBS ukitumia EBS direct APIs](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Rejeleo la snapshot la Azure CLI](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [Usalama wa libguestfs](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
