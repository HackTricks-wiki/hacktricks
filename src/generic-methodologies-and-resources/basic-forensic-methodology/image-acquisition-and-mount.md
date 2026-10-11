# इमेज अधिग्रहण और माउंट करना

{{#include ../../banners/hacktricks-training.md}}

## अधिग्रहण

> हमेशा **read-only** तरीके से अधिग्रहण करें और **कॉपी करते समय hash करें**। मूल डिवाइस को **write-blocked** रखें और केवल सत्यापित कॉपियों पर काम करें।

स्रोत का make, model, serial number और size; टूल और version; timestamps; operator; destination; errors; तथा acquisition/verification hashes दर्ज करें। एक archive image सुरक्षित रखें और उसकी अलग working copy की जाँच करें।<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd`, `dd` कार्यप्रवाह में तुरंत hashing, आउटपुट सत्यापन, त्रुटि लॉगिंग और विभाजित आउटपुट जोड़ता है। `hof=` hash-सत्यापित आउटपुट चुनता है; `hash=`, `hlog=`, `log=` और `bufsz=` अलग-अलग operands हैं।<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager, raw/dd, EWF और legacy AFF output के लिए एक graphical, multithreaded Linux imager है। **AFF और AFF4 अलग-अलग formats हैं**; Guymager AFF4 output का समर्थन नहीं बताता। Acquisition dialog में SHA-256 और destination verification enable करें, फिर इसे `sudo guymager` से शुरू करें।<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

AFF4 v1.0 specification, virtualized storage, arbitrary metadata, extensible compression और hashing, तथा high-throughput operation वाले forensic container को परिभाषित करती है।<sup>[[1]](#references)</sup>

Canonical C/C++ implementation में source के लिए `-i` और AFF4 volume के लिए `-o` का उपयोग होता है। Acquisition baseline के रूप में एक external container hash बनाएँ और सुरक्षित रखें।<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

FTK Imager के मौजूदा दस्तावेज़ों में hash verification के साथ raw/DD, E01 और AFF आउटपुट का उल्लेख है। इसके AFF आउटपुट को AFF4 न कहें।<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### EWF tools (libewf)

बिना निगरानी acquisition के लिए, target `-t` है, case metadata में `-C/-D/-E/-e` इस्तेमाल होते हैं, `-d sha256` SHA-256 जोड़ता है, और `-l` acquisition errors और digests रिकॉर्ड करता है। Analysis से पहले पूरे segment set को verify करें।<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Cloud disks की imaging

Provider snapshot एक point-in-time collection source है, अपने-आप में application-consistent forensic image नहीं। EBS snapshot guest द्वारा अभी भी cache किए गए data को शामिल नहीं करता; writes रोकें, application को quiesce करें, data volume को unmount करें, या response plan अनुमति देता हो तो उस instance को stop करें जिसका root volume capture किया जा रहा है।<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

EBS snapshots को ऐसी फ़ाइलों के रूप में वर्णित न करें जिन्हें सीधे S3 में कॉपी किया जा सकता है। वॉल्यूम बनाए बिना ब्लॉक इमेज को फिर से बनाने के लिए, `ListSnapshotBlocks` से आवंटित ब्लॉक्स की सूची प्राप्त करें, `GetSnapshotBlock` से हर 512 KiB ब्लॉक फ़ेच करें, लौटाए गए checksum को मान्य करें और sparse snapshot में अनुपस्थित ब्लॉक इंडेक्स को शून्यों से भरें।<sup>[[14]](#references)</sup>

Azure के लिए, snapshot बनाएँ, कम समय के लिए मान्य **read-only** SAS जारी करें, VHD डाउनलोड करें, पहुँच रद्द करें और परिणाम का hash निकालें। हर डिस्क का snapshot अलग-अलग लें, जब तक collection mechanism समन्वित consistency प्रदान न करता हो।<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Mount

### Images को hostile input मानें

दुर्भावनापूर्ण filesystem, host kernel के partition और filesystem parsers को निशाना बना सकता है। QEMU स्पष्ट रूप से चेतावनी देता है कि mounting के लिए किसी untrusted guest image को host NBD से connect न करें, और libguestfs की सलाह है कि untrusted guest filesystem को loop या `kpartx` के ज़रिए सीधे कभी mount न करें।<sup>[[2]](#references)[[16]](#references)</sup>

अज्ञात या attacker-controlled image के लिए `guestmount` को प्राथमिकता दें। यह एक छोटे appliance के अंदर guest को parse और mount करता है, फिर FUSE के ज़रिए files उपलब्ध कराता है। Auto-detection के बजाय ज्ञात format को स्पष्ट रूप से निर्दिष्ट करें और appliance के हिस्से को read-only रखें।<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

यदि inspection से OS का पता न चले, तो `-i` की जगह कोई explicit guest device दें, जैसे `-m /dev/sda2`। Encrypted LUKS volumes को `--key` selectors के साथ दिया जा सकता है; key को shell history में सीधे डालने से बचें।<sup>[[17]](#references)</sup>

### Direct host mount चुनना

Direct host mount का उपयोग केवल trusted images या disposable analysis VM में करें:

1. जब original partition table की ज़रूरत हो, तो **पूरी disk** mount करें।
2. जब आपको केवल एक volume की ज़रूरत हो, तो **single partition image** mount करें।
3. Attachment को read-only रखें और image format स्पष्ट रूप से बताएं। Filesystem को भी read-only mount करें। केवल `ro` देने से ext3/ext4 journal replay नहीं रुकता, इसलिए dirty ext filesystems के लिए `ro,noload` इस्तेमाल करें।<sup>[[2]](#references)[[3]](#references)</sup>

Sector size 512 bytes न होने या partition metadata क्षतिग्रस्त होने पर `mmls` उपयोगी है; `-b` में actual device-sector size दें। Partition और filesystem analysis यहाँ जारी रखें:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Raw images (dd, AFF4-extracted)

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

काम पूरा होने पर अलग करें:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

qcow2, VMDK या VHD/VHDX के लिए, विश्वसनीय स्रोत से फ़ॉर्मैट की पुष्टि करें या उसे डिस्पोज़ेबल analysis VM के अंदर जाँचें, फिर `--format=raw` को स्पष्ट फ़ॉर्मैट से बदलें। अविश्वसनीय इनपुट के लिए होस्ट-साइड फ़ॉर्मैट ऑटो-डिटेक्शन पर कभी भरोसा न करें।<sup>[[2]](#references)</sup>

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

फ़ाइलसिस्टम-विशिष्ट no-replay mounts के लिए, ext3/ext4 में `noload` का उपयोग होता है, जबकि XFS में `norecovery` का उपयोग होता है और इसके लिए read-only mode आवश्यक है।<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` एक virtual raw view उपलब्ध करा सकता है, लेकिन उस view में मूल partition table अभी भी मौजूद होती है। पूरी disk file को filesystem के रूप में mount करने के बजाय, इसे उसी `mmls`, isolated `guestmount` या read-only NBD workflow में दें।<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### BitLocker volumes

दोनों layers पर read-only mode का उपयोग करें। बिना value के `-u` देने पर password के लिए prompt आता है, जिससे password process arguments या shell history में शामिल नहीं होता।<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

LUKS या LVM के लिए, `guestmount -i --ro` को प्राथमिकता दें; इसका appliance, host पर किसी बाहरी volume group को activate किए बिना, आम encrypted और logical-volume layouts की जाँच कर सकता है।<sup>[[17]](#references)</sup>

### kpartx helpers

`kpartx` host पर device-mapper nodes बनाता है, इसलिए यह अविश्वसनीय images के लिए उपयुक्त नहीं है। जब direct mapping उचित हो, तो `-r` जोड़ें ताकि partition mappings read-only रहें, और mappings हटाने के लिए वही image path दें जिसका उपयोग उन्हें बनाने में किया था।<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### सामान्य mount त्रुटियाँ और समाधान

| त्रुटि | सामान्य कारण | सुरक्षित अगला कदम |
|-------|---------------|----------------|
| `cannot mount ... read-only` | Dirty journaled filesystem | ext4 `ro,noload` जैसे filesystem-specific no-replay विकल्प का उपयोग करें |
| `bad superblock ...` | गलत partition/sector offset या क्षतिग्रस्त filesystem | `mmls` से sector size और offset की पुष्टि करें; `fsck -n` केवल सत्यापित कॉपी पर चलाएँ |
| `unknown filesystem type 'LVM2_member'` | चुना गया partition एक LVM physical volume है | libguestfs को इसकी जाँच करने दें, या manual LVM activation को disposable VM में अलग रखें |

### सफ़ाई

Backing devices को disconnect करने से पहले filesystems को unmount करें। EWF/xmount के लिए FUSE layer और बनाए गए किसी भी crypt या device-mapper mapping को भी हटाएँ:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [AFF4 मानक विनिर्देश (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd दस्तावेज़](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [mount(8) Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [SGI XFS फ़ाइल सिस्टम (Linux kernel दस्तावेज़)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [डिजिटल साक्ष्य संग्रह के लिए SWGDE की सर्वोत्तम प्रक्रियाएँ](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [Computer Forensic Acquisitions के लिए SWGDE की सर्वोत्तम प्रक्रियाएँ](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [dc3dd(1) मैनुअल पृष्ठ](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Guymager होमपेज और कॉन्फ़िगरेशन दस्तावेज़](https://guymager.sourceforge.io/)
- [9] [c-aff4 दस्तावेज़](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Exterro FTK Imager फ़ॉर्मैट और सत्यापन](https://www.exterro.com/digital-forensics-software)
- [11] [libewf ewfacquire(1) मैनुअल](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [libewf ewfverify(1) मैनुअल](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Amazon EBS snapshots बनाएँ](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [EBS direct APIs के साथ Amazon EBS snapshots पढ़ें](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Azure CLI snapshot संदर्भ](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [libguestfs सुरक्षा](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
