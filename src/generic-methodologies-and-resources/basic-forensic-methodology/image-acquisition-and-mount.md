# Отримання образу та монтування

{{#include ../../banners/hacktricks-training.md}}

## Отримання

> Завжди отримуйте дані **лише для читання** й **обчислюйте хеш під час копіювання**. Захистіть оригінальний пристрій від запису й працюйте лише з перевіреними копіями.

Зафіксуйте виробника, модель, серійний номер і обсяг джерела, інструмент і його версію, часові мітки, оператора, місце призначення, помилки, а також хеші отриманих даних і перевірки. Збережіть архівний образ і досліджуйте окрему робочу копію.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` додає до робочого процесу `dd` хешування на льоту, перевірку вихідних даних, ведення журналу помилок і розділення вихідних даних. `hof=` вибирає вихідні дані, для яких перевіряється хеш; `hash=`, `hlog=`, `log=` і `bufsz=` — це окремі операнди.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager — це графічний багатопотоковий засіб створення образів для Linux із підтримкою форматів raw/dd, EWF і застарілого AFF. **AFF і AFF4 — це різні формати**; Guymager не заявляє про підтримку виводу AFF4. Увімкніть SHA-256 і перевірку цільового пристрою в діалоговому вікні отримання образу, а потім запустіть його командою `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

Специфікація AFF4 v1.0 визначає криміналістичний контейнер із віртуалізованим сховищем, довільними метаданими, розширюваним стисканням і хешуванням та високою пропускною здатністю.<sup>[[1]](#references)</sup>

У канонічній реалізації на C/C++ параметр `-i` задає джерело, а `-o` — том AFF4. Створіть і збережіть зовнішній хеш контейнера як базову контрольну суму отриманого образу.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

У поточній документації FTK Imager зазначено підтримку форматів виводу raw/DD, E01 і AFF із перевіркою хешів. Не позначайте його формат AFF як AFF4.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### Інструменти EWF (libewf)

Для автоматизованого отримання образу ціль задається параметром `-t`, метадані справи — параметрами `-C/-D/-E/-e`, `-d sha256` додає SHA-256, а `-l` записує помилки отримання образу та дайджести. Перед аналізом перевірте повний набір сегментів.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Створення образів хмарних дисків

Знімок постачальника — це джерело збору даних у певний момент часу, а не автоматично криміналістичний образ, узгоджений із застосунком. Знімок EBS не охоплює дані, які досі кешуються гостьовою системою; призупиніть запис, переведіть застосунок у стан спокою, відмонтуйте том із даними або зупиніть екземпляр, якщо знімається його кореневий том, коли це дозволяє план реагування.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

Не описуйте EBS snapshots як файли, які можна просто скопіювати в S3. Щоб відновити образ блоків без створення тому, перелічіть виділені блоки за допомогою `ListSnapshotBlocks`, отримайте кожен блок розміром 512 KiB за допомогою `GetSnapshotBlock`, перевірте отриману контрольну суму та заповніть нулями індекси блоків, відсутніх у розрідженому snapshot.<sup>[[14]](#references)</sup>

Для Azure створіть snapshot, видайте короткостроковий SAS лише для читання, завантажте VHD, відкличте доступ і обчисліть хеш результату. Створюйте snapshot кожного диска окремо, якщо механізм збору не забезпечує узгодженість.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Монтування

### Вважайте образи ворожими вхідними даними

Шкідлива файлова система може атакувати парсери розділів і файлових систем ядра хоста. QEMU прямо застерігає від підключення ненадійного образу гостьової системи до NBD хоста для монтування, а libguestfs рекомендує ніколи не монтувати файлову систему ненадійної гостьової системи безпосередньо за допомогою loop або `kpartx`.<sup>[[2]](#references)[[16]](#references)</sup>

Для невідомого образу або образу, контрольованого зловмисником, надавайте перевагу `guestmount`. Він аналізує та монтує гостьову систему всередині невеликого appliance, а потім надає доступ до файлів через FUSE. Замість автоматичного визначення формату примусово вкажіть відомий формат і залиште appliance у режимі лише для читання.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

Якщо під час перевірки не вдається визначити ОС, замініть `-i` на явний гостьовий пристрій, наприклад `-m /dev/sda2`. Зашифровані томи LUKS можна вказати за допомогою селекторів `--key`; не вводьте ключ безпосередньо в історію shell.<sup>[[17]](#references)</sup>

### Вибір прямого монтування на хості

Використовуйте пряме монтування на хості лише для довірених образів або у тимчасовій VM для аналізу:

1. Монтуйте **весь диск**, якщо потрібна його початкова таблиця розділів.
2. Монтуйте **образ окремого розділу**, якщо потрібен лише один том.
3. Зробіть підключення доступним лише для читання та примусово вкажіть формат образу. Файлову систему також монтуйте лише для читання. Самого `ro` недостатньо, щоб заборонити відтворення журналу ext3/ext4, тому для файлових систем ext із незбереженими змінами використовуйте `ro,noload`.<sup>[[2]](#references)[[3]](#references)</sup>

`mmls` стане в пригоді, якщо розмір сектора відрізняється від 512 байтів або метадані розділів пошкоджені; `-b` задає фактичний розмір сектора пристрою. Продовжте аналіз розділів і файлових систем тут:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Необроблені образи (dd, витягнуті з AFF4)

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

Відмонтуйте після завершення:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

Для qcow2, VMDK або VHD/VHDX визначте формат за надійним джерелом походження або перевірте його у тимчасовій VM для аналізу, а потім замініть `--format=raw` на явне зазначення формату. Ніколи не покладайтеся на автоматичне визначення формату на хості для недовірених даних.<sup>[[2]](#references)</sup>

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

Для файлових систем, що підтримують монтування без повторного відтворення журналу, ext3/ext4 використовують `noload`, а XFS — `norecovery` і вимагає режиму лише для читання.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` може надати віртуальне представлення raw, але воно все одно містить оригінальну таблицю розділів. Передайте його в той самий робочий процес із `mmls`, ізольованим `guestmount` або NBD лише для читання замість монтування файлу всього диска як файлової системи.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### томи BitLocker

Використовуйте режим лише для читання на обох рівнях. `-u` без значення запитує пароль, що дає змогу не вказувати його в аргументах процесу чи історії командної оболонки.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

Для LUKS або LVM надавайте перевагу `guestmount -i --ro`: його appliance може перевіряти поширені схеми шифрування та логічних томів, не активуючи на хості чужу групу томів.<sup>[[17]](#references)</sup>

### Допоміжні засоби kpartx

`kpartx` створює на хості вузли device-mapper, тому не підходить для роботи зі шкідливими образами. Якщо пряме зіставлення виправдане, додайте `-r`, щоб зіставлення розділів були доступні лише для читання, а потім видаліть зіставлення, передавши той самий шлях до образу, який використовували для їх створення.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Поширені помилки монтування та способи їх усунення

| Помилка | Типова причина | Безпечний наступний крок |
|-------|---------------|----------------|
| `cannot mount ... read-only` | Файлова система з журналюванням має незавершені зміни в журналі | використайте специфічний для файлової системи параметр вимкнення відтворення журналу, наприклад `ro,noload` для ext4 |
| `bad superblock ...` | Неправильний розділ або зсув сектора чи пошкоджена файлова система | перевірте розмір сектора та зсув за допомогою `mmls`; запускайте `fsck -n` лише для перевіреної копії |
| `unknown filesystem type 'LVM2_member'` | Вибраний розділ є фізичним томом LVM | дозвольте libguestfs перевірити його або ізолюйте ручну активацію LVM у одноразовій VM |

### Очищення

Перед від’єднанням базових пристроїв відмонтуйте файлові системи. Також видаліть шар FUSE для EWF/xmount і всі створені зіставлення crypt або device-mapper:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [Специфікація стандарту AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Документація QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Сторінка посібника Linux mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Файлова система SGI XFS (документація ядра Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [Рекомендації SWGDE щодо найкращих практик збирання цифрових доказів](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [Рекомендації SWGDE щодо найкращих практик комп’ютерної криміналістики під час створення копій](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [Сторінка посібника dc3dd(1)](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Домашня сторінка Guymager і документація з налаштування](https://guymager.sourceforge.io/)
- [9] [Документація c-aff4](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Формати та перевірка Exterro FTK Imager](https://www.exterro.com/digital-forensics-software)
- [11] [Посібник libewf ewfacquire(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [Посібник libewf ewfverify(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Створення знімків Amazon EBS](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Читання знімків Amazon EBS за допомогою прямих API EBS](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Довідник Azure CLI для знімків](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [Безпека libguestfs](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
