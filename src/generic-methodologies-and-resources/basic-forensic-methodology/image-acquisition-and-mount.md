# 镜像获取与挂载

{{#include ../../banners/hacktricks-training.md}}

## 获取

> 始终以**只读**方式获取，并在**复制时计算哈希**。将原始设备保持为**写保护**状态，只对已验证的副本进行操作。

记录源设备的制造商、型号、序列号和容量，以及工具及其版本、时间戳、操作人员、目标位置、错误和获取/验证哈希。保留归档镜像，并使用单独的工作副本进行检查。<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` 为 `dd` 工作流添加了实时哈希计算、输出验证、错误日志记录和拆分输出功能。`hof=` 用于选择经过哈希验证的输出；`hash=`、`hlog=`、`log=` 和 `bufsz=` 是独立的操作数。<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager 是一款适用于 Linux 的图形化多线程映像工具，可输出 raw/dd、EWF 和旧版 AFF 格式。**AFF 和 AFF4 是不同的格式**；Guymager 未标明支持 AFF4 输出。在采集对话框中启用 SHA-256 和目标验证，然后使用 `sudo guymager` 启动它。<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

AFF4 v1.0 规范定义了一种取证容器，支持虚拟化存储、任意元数据、可扩展的压缩与哈希，以及高吞吐量操作。<sup>[[1]](#references)</sup>

规范的 C/C++ 实现使用 `-i` 指定源，使用 `-o` 指定 AFF4 卷。创建并保留一个外部容器哈希，作为采集基准。<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

当前 FTK Imager 文档说明支持输出 raw/DD、E01 和 AFF 格式，并进行哈希验证。不要将其 AFF 输出标记为 AFF4。<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### EWF 工具 (libewf)

对于无人值守采集，目标参数为 `-t`，案件元数据使用 `-C/-D/-E/-e`，`-d sha256` 会添加 SHA-256，`-l` 会记录采集错误和摘要。分析前请验证已完成的分段集。<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### 云磁盘成像

云服务提供商的快照是某一时刻的数据采集源，并不自动构成应用一致的取证镜像。EBS 快照不包含仍缓存在 guest 中的数据；如果响应计划允许，应暂停写入、静默应用、卸载数据卷，或在捕获根卷时停止实例。<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

不要将 EBS snapshots 描述成可以直接复制到 S3 的文件。若要在不创建 volume 的情况下重建 block image，请使用 `ListSnapshotBlocks` 枚举已分配的 blocks，使用 `GetSnapshotBlock` 获取每个 512 KiB 的 block，验证返回的 checksum，并将 sparse snapshot 中缺失的 block indexes 填充为零。<sup>[[14]](#references)</sup>

对于 Azure，创建 snapshot，生成有效期较短的**只读** SAS，下载 VHD，撤销访问权限，并对结果进行哈希计算。除非采集机制能够提供协调一致性，否则应分别为每个 disk 创建 snapshot。<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## 挂载

### 将镜像视为恶意输入

恶意文件系统可能会攻击主机内核的分区和文件系统解析器。QEMU 明确警告，不要将不可信的 guest 镜像连接到主机 NBD 进行挂载；libguestfs 也建议绝不要直接使用 loop 或 `kpartx` 挂载不可信的 guest 文件系统。<sup>[[2]](#references)[[16]](#references)</sup>

对于未知或由攻击者控制的镜像，优先使用 `guestmount`。它会在一个小型 appliance 中解析并挂载 guest，然后通过 FUSE 暴露文件。指定已知格式，而不要使用自动检测，并确保 appliance 侧为只读。<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

如果检查无法判断操作系统，请将 `-i` 替换为明确的 guest 设备，例如 `-m /dev/sda2`。可以使用 `--key` 选择器提供加密的 LUKS 卷；避免将密钥直接写入 shell 历史记录。<sup>[[17]](#references)</sup>

### 选择直接挂载到主机

仅对可信镜像或一次性分析 VM 使用直接挂载：

1. 需要原始分区表时，挂载**整块磁盘**。
2. 只需要一个卷时，挂载**单个分区镜像**。
3. 将设备设为只读，并强制指定镜像格式。文件系统也要以只读方式挂载。仅使用 `ro` 无法阻止 ext3/ext4 重放日志，因此对于存在未完成写入的 ext 文件系统，请使用 `ro,noload`。<sup>[[2]](#references)[[3]](#references)</sup>

当扇区大小不是 512 字节或分区元数据已损坏时，`mmls` 很有用；`-b` 用于指定实际的设备扇区大小。在此继续进行分区和文件系统分析：<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Raw 镜像（dd、从 AFF4 提取）

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

完成后卸载：

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

对于 qcow2、VMDK 或 VHD/VHDX，应根据可信来源确定格式，或在一次性分析 VM 中检查格式，然后将 `--format=raw` 替换为明确指定的格式。切勿依赖主机端对不可信输入进行格式自动检测。<sup>[[2]](#references)</sup>

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

对于文件系统特定的 no-replay 挂载，ext3/ext4 使用 `noload`，而 XFS 使用 `norecovery`，并且要求只读模式。<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` 可以提供虚拟原始视图，但该视图仍包含原始分区表。应将其交给相同的 `mmls`、隔离的 `guestmount` 或只读 NBD 工作流处理，而不是将整个磁盘文件作为文件系统挂载。<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### BitLocker 卷

在两个层级都使用只读模式。不带值的 `-u` 会提示输入密码，避免将密码放入进程参数或 shell 历史记录中。<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

对于 LUKS 或 LVM，优先使用 `guestmount -i --ro`；其 appliance 可以检查常见的加密和逻辑卷布局，而无需在主机上激活外来的卷组。<sup>[[17]](#references)</sup>

### kpartx 辅助工具

`kpartx` 会创建主机 device-mapper 节点，因此不适用于不可信镜像。如果确有理由进行直接映射，请添加 `-r`，使分区映射为只读，并使用创建映射时相同的镜像路径来移除映射。<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### 常见挂载错误及修复方法

| 错误 | 常见原因 | 安全的后续步骤 |
|-------|---------------|----------------|
| `cannot mount ... read-only` | 日志文件系统未正常卸载 | 使用文件系统专用的禁用日志重放选项，例如 ext4 的 `ro,noload` |
| `bad superblock ...` | 分区/扇区偏移错误或文件系统损坏 | 使用 `mmls` 确认扇区大小和偏移；仅在已验证的副本上运行 `fsck -n` |
| `unknown filesystem type 'LVM2_member'` | 选中的分区是 LVM 物理卷 | 让 libguestfs 检查，或在一次性 VM 中单独手动激活 LVM |

### 清理

断开后端设备前，请先卸载文件系统。还要移除 EWF/xmount 的 FUSE 层，以及已创建的任何 crypt 或 device-mapper 映射：

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [AFF4 标准规范（Advanced Forensic Format v4）](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd 文档](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [mount(8) Linux 手册页](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [SGI XFS 文件系统（Linux 内核文档）](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [SWGDE 数字证据收集最佳实践](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [SWGDE 计算机取证采集最佳实践](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [dc3dd(1) 手册页](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Guymager 主页和配置文档](https://guymager.sourceforge.io/)
- [9] [c-aff4 文档](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Exterro FTK Imager 格式与验证](https://www.exterro.com/digital-forensics-software)
- [11] [libewf ewfacquire(1) 手册](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [libewf ewfverify(1) 手册](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [创建 Amazon EBS 快照](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [使用 EBS direct APIs 读取 Amazon EBS 快照](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Azure CLI 快照参考](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [libguestfs 安全性](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
