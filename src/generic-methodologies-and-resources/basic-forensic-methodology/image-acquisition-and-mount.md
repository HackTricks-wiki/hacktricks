# イメージ取得とマウント

{{#include ../../banners/hacktricks-training.md}}

## 取得

> 常に**読み取り専用**で取得し、コピー中に**hashを計算**してください。元のデバイスは**書き込みをブロック**し、検証済みのコピーのみを使用してください。

取得元のメーカー、モデル、シリアル番号、サイズ、ツールとバージョン、タイムスタンプ、担当者、保存先、エラー、取得時と検証時のhashを記録してください。アーカイブイメージを保管し、別の作業用コピーを調査してください。<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` は、`dd` のワークフローにオンザフライのハッシュ計算、出力の検証、エラーログ記録、出力の分割を追加します。`hof=` はハッシュ検証済みの出力を指定します。`hash=`、`hlog=`、`log=`、`bufsz=` はそれぞれ独立したオペランドです。<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymagerは、raw/dd、EWF、レガシーAFF形式で出力できる、Linux用のグラフィカルなマルチスレッドイメージャーです。**AFFとAFF4は異なる形式**であり、GuymagerはAFF4形式での出力を謳っていません。取得ダイアログでSHA-256と出力先の検証を有効にし、`sudo guymager`で起動します。<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

AFF4 v1.0仕様では、仮想化ストレージ、任意のメタデータ、拡張可能な圧縮とハッシュ、高スループット処理を備えたフォレンジックコンテナが定義されています。<sup>[[1]](#references)</sup>

標準的なC/C++実装では、ソースに`-i`、AFF4ボリュームに`-o`を使用します。取得時のベースラインとして、コンテナのハッシュを外部に作成して保管してください。<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

FTK Imagerの現在のドキュメントでは、ハッシュ検証付きのraw/DD、E01、AFF形式での出力が案内されています。AFF出力をAFF4と表記しないでください。<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### EWF tools (libewf)

無人取得では、対象に `-t` を指定し、ケースメタデータには `-C/-D/-E/-e` を使用します。`-d sha256` で SHA-256 を追加し、`-l` で取得時のエラーとダイジェストを記録します。分析の前に、完了したセグメント一式を検証してください。<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### クラウドディスクのイメージ取得

プロバイダーのスナップショットは特定時点のデータを収集する手段であり、自動的にアプリケーション整合性のあるフォレンジックイメージになるわけではありません。EBS スナップショットにはゲスト側でまだキャッシュされているデータは含まれません。対応計画で許可される場合は、書き込みを一時停止し、アプリケーションを静止状態にし、データボリュームをアンマウントするか、ルートボリュームを取得するインスタンスを停止してください。<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

EBS snapshotを、S3にそのままコピーできるファイルとして説明してはいけません。ボリュームを作成せずにブロックイメージを再構築するには、`ListSnapshotBlocks`で割り当て済みブロックを列挙し、`GetSnapshotBlock`で各512 KiBブロックを取得して、返されたチェックサムを検証します。スパーススナップショットに存在しないブロックインデックスはゼロで埋めてください。<sup>[[14]](#references)</sup>

Azureでは、スナップショットを作成し、有効期間の短い**読み取り専用**SASを発行して、VHDをダウンロードし、アクセスを取り消してから結果のハッシュ値を計算します。収集方法で整合性を協調して確保できる場合を除き、ディスクごとに個別にスナップショットを作成してください。<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## マウント

### イメージを信頼できない入力として扱う

悪意のあるファイルシステムは、ホストカーネルのパーティションパーサーやファイルシステムパーサーを標的にする可能性があります。QEMUは、信頼できないゲストイメージをホストのNBDに接続してマウントしないよう明示的に警告しており、libguestfsも、信頼できないゲストファイルシステムをloopや`kpartx`で直接マウントしないよう推奨しています。<sup>[[2]](#references)[[16]](#references)</sup>

正体不明または攻撃者が管理するイメージには、`guestmount`を使うことを推奨します。`guestmount`は小規模なアプライアンス内でゲストを解析してマウントし、その後、FUSE経由でファイルを公開します。自動検出ではなく既知のフォーマットを指定し、アプライアンス側を読み取り専用にしてください。<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

OSを検査しても特定できない場合は、`-i`を`-m /dev/sda2`などの明示的なguest deviceに置き換えます。暗号化されたLUKSボリュームは`--key`セレクターで指定できます。キーをシェルの履歴に残さないようにしてください。<sup>[[17]](#references)</sup>

### 直接ホストマウントの選択

直接ホストマウントは、信頼できるイメージか、使い捨ての分析VMでのみ使用してください。

1. 元のパーティションテーブルが必要な場合は、**ディスク全体**をマウントします。
2. 1つのボリュームだけが必要な場合は、**単一パーティションのイメージ**をマウントします。
3. アタッチを読み取り専用にし、イメージ形式を明示します。ファイルシステムも読み取り専用でマウントしてください。`ro`だけではext3/ext4のジャーナル再生を防げないため、dirtyなextファイルシステムでは`ro,noload`を使います。<sup>[[2]](#references)[[3]](#references)</sup>

セクターサイズが512バイトでない場合や、パーティションのメタデータが損傷している場合は、`mmls`が役立ちます。`-b`には実際のデバイスセクターサイズを指定します。パーティションとファイルシステムの分析はこちらで続けてください。<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Rawイメージ（dd、AFF4から抽出）

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

完了したら取り外す：

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

qcow2、VMDK、VHD/VHDX の場合は、信頼できる来歴情報から形式を特定するか、使い捨ての解析 VM 内で形式を確認してから、`--format=raw` を明示的な形式に置き換えてください。信頼できない入力に対して、ホスト側の形式自動検出に頼らないでください。<sup>[[2]](#references)</sup>

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

ファイルシステム固有の no-replay マウントでは、ext3/ext4 は `noload` を使用し、XFS は `norecovery` を使用して読み取り専用モードにする必要があります。<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` は仮想の raw view を公開できますが、その view には元のパーティションテーブルが含まれています。ディスク全体のファイルをファイルシステムとしてマウントするのではなく、同じ `mmls`、隔離した `guestmount`、または読み取り専用 NBD のワークフローに渡してください。<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### BitLocker ボリューム

両方のレイヤーで読み取り専用モードを使用します。値を指定せずに `-u` を指定するとパスワードの入力を求められるため、パスワードがプロセス引数やシェル履歴に残りません。<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

LUKS または LVM の場合は、`guestmount -i --ro` を優先してください。内蔵の appliance で、ホスト上の外部ボリュームグループを有効化せずに、一般的な暗号化レイアウトや論理ボリュームレイアウトを調査できます。<sup>[[17]](#references)</sup>

### kpartx ヘルパー

`kpartx` はホストの device-mapper ノードを作成するため、悪意のあるイメージには適していません。直接マッピングする必要がある場合は、パーティションのマッピングを読み取り専用にするために `-r` を追加し、作成時と同じイメージパスを指定してマッピングを削除してください。<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### よくあるマウントエラーと対処方法

| エラー | 典型的な原因 | 安全な次の手順 |
|-------|---------------|----------------|
| `cannot mount ... read-only` | ジャーナリングファイルシステムのジャーナルが未処理 | ext4 の `ro,noload` のような、ファイルシステム固有の再生を行わないオプションを使う |
| `bad superblock ...` | パーティションまたはセクターオフセットの誤り、あるいはファイルシステムの破損 | `mmls` でセクターサイズとオフセットを確認する。確認済みのコピーに対してのみ `fsck -n` を実行する |
| `unknown filesystem type 'LVM2_member'` | 選択したパーティションが LVM 物理ボリューム | libguestfs に検査させるか、使い捨て VM 内で手動の LVM アクティベーションを隔離して行う |

### クリーンアップ

バックエンドデバイスを切断する前にファイルシステムをアンマウントします。また、EWF/xmount 用の FUSE レイヤーと、作成した crypt または device-mapper のマッピングも削除します。

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [AFF4 標準仕様（Advanced Forensic Format v4）](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd ドキュメント](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [mount(8) Linux マニュアルページ](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [SGI XFS ファイルシステム（Linux カーネルドキュメント）](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [デジタル証拠収集のベストプラクティス](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [コンピュータフォレンジック取得のベストプラクティス](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [dc3dd(1) マニュアルページ](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Guymager ホームページおよび設定ドキュメント](https://guymager.sourceforge.io/)
- [9] [c-aff4 ドキュメント](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Exterro FTK Imager の形式と検証](https://www.exterro.com/digital-forensics-software)
- [11] [libewf ewfacquire(1) マニュアル](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [libewf ewfverify(1) マニュアル](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Amazon EBS スナップショットの作成](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [EBS direct APIs を使用した Amazon EBS スナップショットの読み取り](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Azure CLI スナップショットリファレンス](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [libguestfs のセキュリティ](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
