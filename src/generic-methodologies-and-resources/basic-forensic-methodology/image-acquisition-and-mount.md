# Image Acquisition & Mount

{{#include ../../banners/hacktricks-training.md}}

## Acquisition

> Always acquire **read-only** and **hash while you copy**. Keep the original device **write-blocked** and work only on verified copies.

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` is the actively maintained fork of dcfldd (DoD Computer Forensics Lab dd).

```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```

### Guymager  
Graphical, multithreaded imager that supports **raw (dd)**, **EWF (E01/EWFX)** and **AFF4** output with parallel verification. Available in most Linux repos (`apt install guymager`).

```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```

### AFF4 (Advanced Forensics Format 4)

The AFF4 v1.0 specification, authored by Bradley L. Schatz and Michael I. Cohen, defines a forensic container with virtualized storage, arbitrary metadata, extensible compression and hashing, and high-throughput operation.<sup>[[1]](#references)</sup>

```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```

### FTK Imager (Windows & Linux)

You can [download FTK Imager](https://accessdata.com/product-download) and create **raw, E01 or AFF4** images:

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### EWF tools (libewf)

```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```

### Imaging Cloud Disks

*AWS* – create a **forensic snapshot** without shutting down the instance:

```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```

*Azure* – use `az snapshot create` and export to a SAS URL.


## Mount

### Choosing the right approach

1. Mount the **whole disk** when you want the original partition table (MBR/GPT).
2. Mount a **single partition file** when you only need one volume.
3. Keep image attachments read-only (for example, qemu-nbd's `--read-only`).<sup>[[2]](#references)</sup> Mount filesystems read-only (`-o ro`).<sup>[[3]](#references)</sup> Work on **copies**.

### Raw images (dd, AFF4-extracted)

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

Detach when finished:
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

For filesystem-specific no-replay mounts, ext3/ext4 use `noload`, while XFS uses `norecovery` and requires read-only mode.<sup>[[3]](#references)[[4]](#references)</sup>

Alternatively convert on the fly with **xmount**:

```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```

### LVM / BitLocker / VeraCrypt volumes

After attaching the block device (loop or nbd):

```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

### kpartx helpers

`kpartx` maps partitions from an image to `/dev/mapper/` automatically:

```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```

### Common mount errors & fixes

For a dirty ext3/ext4 filesystem, use `ro,noload` when journal replay must be prevented.<sup>[[3]](#references)</sup>

| Error | Typical Cause | Fix |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journaled FS (ext4) not cleanly unmounted | use `-o ro,noload` |
| `bad superblock …` | Wrong offset or damaged FS | calculate offset (`sector*size`) or run `fsck -n` on a copy |
| `mount: unknown filesystem type 'LVM2_member'` | LVM container | activate volume group with `vgchange -ay` |

### Clean-up

Remember to **umount** and **disconnect** loop/nbd devices to avoid leaving dangling mappings that can corrupt further work:

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
