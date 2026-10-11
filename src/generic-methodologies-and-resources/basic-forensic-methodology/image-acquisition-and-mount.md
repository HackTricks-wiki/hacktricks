# İmaj Edinimi ve Bağlama

{{#include ../../banners/hacktricks-training.md}}

## Edinim

> Her zaman **salt okunur** şekilde edinin ve **kopyalama sırasında hash alın**. Kaynak cihazı **yazmaya karşı korumalı** tutun ve yalnızca doğrulanmış kopyalar üzerinde çalışın.

Kaynağın üretici, model, seri numarası ve boyut bilgilerini; kullanılan aracı ve sürümünü; zaman damgalarını; operatörü; hedef konumu; hataları ve edinim/doğrulama hash'lerini kaydedin. Bir arşiv imajı saklayın ve ayrı bir çalışma kopyasını inceleyin.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd`, `dd` iş akışına anlık hashing, çıktı doğrulama, hata günlüğü kaydı ve çıktıyı parçalara ayırma özellikleri ekler. `hof=`, hash doğrulamalı bir çıktı seçer; `hash=`, `hlog=`, `log=` ve `bufsz=` ayrı operand'lardır.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager, raw/dd, EWF ve eski AFF çıktısı için grafik arayüzlü, çok iş parçacıklı bir Linux imager’ıdır. **AFF ve AFF4 farklı formatlardır**; Guymager AFF4 çıktısı sunduğunu belirtmez. Acquisition iletişim kutusunda SHA-256 ve hedef doğrulamayı etkinleştirin, ardından `sudo guymager` ile başlatın.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

AFF4 v1.0 spesifikasyonu; sanallaştırılmış depolama, keyfi metadata, genişletilebilir sıkıştırma ve hashing ile yüksek verimli çalışma sunan bir adli bilişim kapsayıcısı tanımlar.<sup>[[1]](#references)</sup>

Standart C/C++ uygulaması, kaynak için `-i`, AFF4 volume için `-o` kullanır. Acquisition temel referansı olarak harici bir kapsayıcı hash’i oluşturup saklayın.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

Güncel FTK Imager belgelerinde hash doğrulamasıyla raw/DD, E01 ve AFF çıktısı desteklendiği belirtiliyor. AFF çıktısını AFF4 olarak adlandırmayın.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### EWF araçları (libewf)

Gözetimsiz edinim için hedef `-t` seçeneğiyle belirtilir; vaka meta verileri `-C/-D/-E/-e` seçeneklerini kullanır, `-d sha256` SHA-256 ekler ve `-l` edinim hatalarını ve özet değerlerini kaydeder. Analizden önce tamamlanmış segment kümesini doğrulayın.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Cloud disklerinin imajını alma

Bir sağlayıcı snapshot'ı, belirli bir andaki veri toplama kaynağıdır; otomatik olarak uygulama tutarlı bir adli imaj değildir. EBS snapshot'ı, konuk sistemin hâlâ önbelleğinde tuttuğu verileri içermez; müdahale planı izin veriyorsa yazma işlemlerini duraklatın, uygulamayı quiesce edin, veri birimini bağdan çıkarın veya kök birimi görüntülenecek bir instance'ı durdurun.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

EBS snapshot'larını S3'e kolayca kopyalanabilen dosyalar olarak tanımlamayın. Bir volume oluşturmadan blok imajını yeniden oluşturmak için `ListSnapshotBlocks` ile ayrılmış blokları listeleyin, her 512 KiB bloğu `GetSnapshotBlock` ile alın, döndürülen checksum değerini doğrulayın ve sparse snapshot'ta bulunmayan blok indekslerini sıfırlarla doldurun.<sup>[[14]](#references)</sup>

Azure için snapshot oluşturun, kısa ömürlü **salt okunur** bir SAS oluşturun, VHD'yi indirin, erişimi iptal edin ve sonucu hash'leyin. Toplama mekanizması koordineli tutarlılık sağlamıyorsa her diskin snapshot'ını ayrı ayrı alın.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Bağlama

### İmajları güvenilmeyen girdi olarak değerlendirin

Kötü amaçlı bir dosya sistemi, ana makinenin kernel bölümleme ve dosya sistemi ayrıştırıcılarını hedef alabilir. QEMU, güvenilmeyen bir guest imajının bağlama amacıyla ana makinenin NBD’sine bağlanmasına karşı açıkça uyarır; libguestfs ise güvenilmeyen bir guest dosya sisteminin loop veya `kpartx` ile doğrudan bağlanmamasını önerir.<sup>[[2]](#references)[[16]](#references)</sup>

Bilinmeyen veya saldırganın kontrolündeki imajlar için `guestmount` kullanmayı tercih edin. İmajı küçük bir appliance içinde ayrıştırıp bağlar, ardından dosyaları FUSE üzerinden sunar. Otomatik algılama yerine bilinen biçimi zorunlu kılın ve appliance tarafını salt okunur tutun.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

İnceleme işletim sistemini belirleyemiyorsa `-i` yerine `-m /dev/sda2` gibi açık bir guest device belirtin. Şifrelenmiş LUKS volume’ları `--key` seçicileriyle sağlayabilirsiniz; anahtarı doğrudan shell geçmişine yazmaktan kaçının.<sup>[[17]](#references)</sup>

### Doğrudan host mount seçimi

Doğrudan host mount işlemini yalnızca güvenilir image’lar veya geçici bir analiz VM’i için kullanın:

1. Orijinal partition table’a ihtiyacınız varsa **tüm diski** mount edin.
2. Yalnızca tek bir volume’a ihtiyacınız varsa **tek bir partition image’ını** mount edin.
3. Bağlantıyı read-only yapın ve image formatını zorunlu belirtin. Filesystem’i de read-only mount edin. Tek başına `ro`, ext3/ext4 journal replay işlemini durdurmaz; bu nedenle sorunlu ext filesystem’lerinde `ro,noload` kullanın.<sup>[[2]](#references)[[3]](#references)</sup>

Sector size 512 byte olmadığında veya partition metadata’sı zarar gördüğünde `mmls` kullanışlıdır; `-b`, gerçek device-sector size değerini belirtir. Partition ve filesystem analizine buradan devam edin:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Raw image’lar (dd, AFF4’ten çıkarılmış)

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

İşiniz bittiğinde ayırın:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

qcow2, VMDK veya VHD/VHDX için formatı güvenilir kaynaktan doğrulayın ya da tek kullanımlık analiz VM’si içinde inceleyin, ardından `--format=raw` yerine açıkça belirtilen formatı kullanın. Güvenilmeyen girdiler için host tarafında formatın otomatik algılanmasına asla güvenmeyin.<sup>[[2]](#references)</sup>

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

Dosya sistemine özgü no-replay mount seçenekleri için ext3/ext4 `noload`, XFS ise `norecovery` kullanır ve salt okunur kip gerektirir.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` sanal bir ham görünüm sunabilir, ancak bu görünüm özgün bölüm tablosunu içerir. Tüm disk dosyasını bir dosya sistemi olarak mount etmek yerine, aynı `mmls`, yalıtılmış `guestmount` veya salt okunur NBD iş akışına verin.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### BitLocker birimleri

Her iki katmanda da salt okunur modu kullanın. Değer belirtilmeden kullanılan `-u`, parola istemi açar; böylece parola işlem argümanlarında veya kabuk geçmişinde yer almaz.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

LUKS veya LVM için `guestmount -i --ro` tercih edin; appliance, ana makinede yabancı bir volume group'u etkinleştirmeden yaygın şifreli ve mantıksal birim düzenlerini inceleyebilir.<sup>[[17]](#references)</sup>

### kpartx yardımcıları

`kpartx`, ana makinede device-mapper düğümleri oluşturur; bu nedenle güvenilmeyen imajlar için uygun değildir. Doğrudan eşleme gerekçelendirilebiliyorsa, bölüm eşlemelerinin salt okunur olması için `-r` ekleyin ve eşlemeleri kaldırırken oluşturmak için kullandığınız imaj yolunun aynısını geçirin.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Yaygın mount hataları ve çözümleri

| Hata | Yaygın neden | Güvenli sonraki adım |
|-------|---------------|----------------|
| `cannot mount ... read-only` | Kirli günlüklemeli dosya sistemi | ext4 `ro,noload` gibi dosya sistemine özgü yeniden oynatmayı devre dışı bırakma seçeneğini kullanın |
| `bad superblock ...` | Yanlış bölüm/sektör ofseti veya hasarlı dosya sistemi | Sektör boyutunu ve ofseti `mmls` ile doğrulayın; `fsck -n` komutunu yalnızca doğrulanmış bir kopyada çalıştırın |
| `unknown filesystem type 'LVM2_member'` | Seçilen bölüm bir LVM fiziksel birimidir | libguestfs'in incelemesine izin verin veya elle LVM etkinleştirme işlemini geçici bir VM'de yalıtın |

### Temizleme

Destekleyen aygıtlarının bağlantısını kesmeden önce dosya sistemlerini ayırın. Ayrıca EWF/xmount için FUSE katmanını ve oluşturulan crypt veya device-mapper eşlemelerini de kaldırın:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [AFF4 Standard Specification (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd belgeleri](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [mount(8) Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [SGI XFS dosya sistemi (Linux kernel belgeleri)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [SWGDE Dijital Kanıt Toplama için En İyi Uygulamalar](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [SWGDE Bilgisayar Adli Bilişim Edinimleri için En İyi Uygulamalar](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [dc3dd(1) kılavuz sayfası](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Guymager ana sayfası ve yapılandırma belgeleri](https://guymager.sourceforge.io/)
- [9] [c-aff4 belgeleri](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Exterro FTK Imager biçimleri ve doğrulama](https://www.exterro.com/digital-forensics-software)
- [11] [libewf ewfacquire(1) kılavuzu](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [libewf ewfverify(1) kılavuzu](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Amazon EBS anlık görüntüleri oluşturma](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [EBS doğrudan API'leriyle Amazon EBS anlık görüntülerini okuma](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Azure CLI anlık görüntü başvurusu](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [libguestfs güvenliği](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
