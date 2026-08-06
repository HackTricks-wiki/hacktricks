# イメージ取得とマウント

{{#include ../../banners/hacktricks-training.md}}


## 取得

> 常に**読み取り専用**で取得し、**コピー中にハッシュを計算**する。元のデバイスは**書き込みブロック**したままにし、検証済みのコピー上でのみ作業する。

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd`は、dcfldd（DoD Computer Forensics Lab dd）からフォークされた、現在も積極的にメンテナンスされているツールです。
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
**raw (dd)**、**EWF (E01/EWFX)**、**AFF4** の出力と並列検証に対応した、グラフィカルなマルチスレッドイメージャー。ほとんどの Linux リポジトリで利用可能（`apt install guymager`）。
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4（Advanced Forensics Format 4）

AFF4は、*非常に*大規模な証拠（スパース、再開可能、cloud-native）向けに設計されたGoogleの最新のイメージング形式です。<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

[FTK Imagerをダウンロード](https://accessdata.com/product-download)して、**raw、E01、またはAFF4**イメージを作成できます:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF ツール（libewf）
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Cloud Disk のイメージ取得

*AWS* – インスタンスをシャットダウンせずに **forensic snapshot** を作成する：
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – `az snapshot create` を使用し、SAS URL にエクスポートします。


## マウント

### 適切なアプローチの選択

1. 元のパーティションテーブル（MBR/GPT）が必要な場合は、**ディスク全体**をマウントします。
2. 1つのボリュームだけが必要な場合は、**単一のパーティションファイル**をマウントします。
3. 常に**読み取り専用**（`-o ro,norecovery`）でマウントし、**コピー**上で作業します。<sup>[[2]](#references)</sup>

### Raw images（dd、AFF4-extracted）
```bash
# Identify partitions
fdisk -l disk.img

# Attach the image to a network block device (does not modify the file)
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 --read-only disk.img

# Inspect partitions
lsblk /dev/nbd0 -o NAME,SIZE,TYPE,FSTYPE,LABEL,UUID

# Mount a partition (e.g. /dev/nbd0p2)
sudo mount -o ro,uid=$(id -u) /dev/nbd0p2 /mnt
```
完了したらデタッチ:
```bash
sudo umount /mnt && sudo qemu-nbd --disconnect /dev/nbd0
```
### EWF (E01/EWFX)
```bash
# 1. Mount the EWF container
mkdir /mnt/ewf
ewfmount evidence.E01 /mnt/ewf

# 2. Attach the exposed raw file via qemu-nbd (safer than loop)
sudo qemu-nbd --connect=/dev/nbd1 --read-only /mnt/ewf/ewf1

# 3. Mount the desired partition
sudo mount -o ro,norecovery /dev/nbd1p1 /mnt/evidence
```
または **xmount** を使用してオンザフライで変換します：
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt ボリューム

ブロックデバイス（loop または nbd）を接続した後:
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx ヘルパー

`kpartx` はイメージ内のパーティションを自動的に `/dev/mapper/` にマッピングします:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### よくある mount エラーと修正方法

| エラー | 典型的な原因 | 修正方法 |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | ジャーナリングFS（ext4）が正常にアンマウントされていない | `-o ro,norecovery` を使用 |
| `bad superblock …` | オフセットが間違っている、またはFSが破損している | オフセット（`sector*size`）を計算するか、コピーに対して `fsck -n` を実行 |
| `mount: unknown filesystem type 'LVM2_member'` | LVMコンテナ | `vgchange -ay` で volume group をアクティベート |

### クリーンアップ

作業の妨げとなるマッピングが残り、以降の作業を破損させる可能性があるため、loop/nbd デバイスの **umount** と **disconnect** を忘れないでください:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## 参考文献

- [1] [AFF4 Standard Specification (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [qemu-nbd マニュアルページ（disk image を安全に mount する方法）](https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html)

{{#include ../../banners/hacktricks-training.md}}
