# イメージの取得とマウント

{{#include ../../banners/hacktricks-training.md}}

## 取得

> 常に **read-only** で取得し、**コピー中にハッシュを計算**してください。元のデバイスは **write-blocked** の状態に保ち、検証済みのコピーのみを使用してください。

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd`は、dcfldd（DoD Computer Forensics Lab dd）から分岐した、現在も積極的にメンテナンスされているforkです。
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
**raw (dd)**、**EWF (E01/EWFX)**、**AFF4** 出力と並列検証に対応した、グラフィカルなマルチスレッド imager。ほとんどの Linux リポジトリで利用可能（`apt install guymager`）。
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4（Advanced Forensics Format 4）

Bradley L. Schatz と Michael I. Cohen が執筆した AFF4 v1.0 仕様は、仮想化ストレージ、任意のメタデータ、拡張可能な圧縮およびハッシュ機能、高スループットの操作を備えたフォレンジックコンテナを定義しています。<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

[FTK Imagerをダウンロード](https://accessdata.com/product-download)して、**raw、E01、またはAFF4**イメージを作成できます。
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF ツール (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### クラウドディスクのイメージ取得

*AWS* – インスタンスをシャットダウンせずに**forensic snapshot**を作成します:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – `az snapshot create` を使用し、SAS URL にエクスポートします。


## マウント

### 適切なアプローチの選択

1. 元のパーティションテーブル（MBR/GPT）が必要な場合は、**ディスク全体**をマウントします。
2. 1つのボリュームだけが必要な場合は、**単一のパーティションファイル**をマウントします。
3. イメージのアタッチは読み取り専用にします（例：qemu-nbd の `--read-only`）。<sup>[[2]](#references)</sup> ファイルシステムは読み取り専用（`-o ro`）でマウントします。<sup>[[3]](#references)</sup> **コピー**上で作業します。

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
完了したら切り離す:
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

# 3. Mount the desired partition (XFS example; use the filesystem-specific option)
sudo mount -o ro,norecovery /dev/nbd1p1 /mnt/evidence
```
ファイルシステム固有の再再生なしマウントでは、ext3/ext4 は `noload` を使用し、XFS は `norecovery` を使用して読み取り専用モードにする必要があります。<sup>[[3]](#references)[[4]](#references)</sup>

または、**xmount** を使用してオンザフライで変換します：
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt ボリューム

block device（loop または nbd）を接続した後:
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx ヘルパー

`kpartx` はイメージからパーティションを自動的に `/dev/mapper/` にマッピングします:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### よくある mount エラーと修正方法

dirty な ext3/ext4 filesystem では、journal replay を防止する必要がある場合に `ro,noload` を使用します。<sup>[[3]](#references)</sup>

| エラー | 典型的な原因 | 修正方法 |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | journaled FS (ext4) が正常に unmount されていない | `-o ro,noload` を使用 |
| `bad superblock …` | offset が間違っている、または FS が破損している | offset (`sector*size`) を計算するか、コピーに対して `fsck -n` を実行 |
| `mount: unknown filesystem type 'LVM2_member'` | LVM container | `vgchange -ay` で volume group を activate |

### クリーンアップ

作業の続行時に破損を引き起こす可能性のある dangling mapping を残さないよう、loop/nbd devices を **umount** して **disconnect** することを忘れないでください：
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [AFF4 Standard Specification (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd documentation](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [mount(8) Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [The SGI XFS filesystem (Linux kernel documentation)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
