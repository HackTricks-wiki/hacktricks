# Image Acquisition & Mount

{{#include ../../banners/hacktricks-training.md}}

## Acquisition

> Always acquire **read-only** and **hash while you copy**. Keep the original device **write-blocked** and work only on verified copies.

Record the source make, model, serial number and size, the tool and version, timestamps, operator, destination, errors and acquisition/verification hashes. Preserve an archive image and examine a separate working copy.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` adds on-the-fly hashing, output verification, error logging and split output to the `dd` workflow. `hof=` selects a hash-verified output; `hash=`, `hlog=`, `log=` and `bufsz=` are separate operands.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager is a graphical, multithreaded Linux imager for raw/dd, EWF and legacy AFF output. **AFF and AFF4 are different formats**; Guymager does not advertise AFF4 output. Enable SHA-256 plus destination verification in the acquisition dialog, then start it with `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

The AFF4 v1.0 specification defines a forensic container with virtualized storage, arbitrary metadata, extensible compression and hashing, and high-throughput operation.<sup>[[1]](#references)</sup>

The canonical C/C++ implementation uses `-i` for the source and `-o` for the AFF4 volume. Create and retain an external container hash as the acquisition baseline.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

Current FTK Imager documentation advertises raw/DD, E01 and AFF output with hash verification. Do not label its AFF output as AFF4.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### EWF tools (libewf)

For unattended acquisition, the target is `-t`, case metadata uses `-C/-D/-E/-e`, `-d sha256` adds SHA-256, and `-l` records acquisition errors and digests. Verify the completed segment set before analysis.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Imaging cloud disks

A provider snapshot is a point-in-time collection source, not automatically an application-consistent forensic image. An EBS snapshot excludes data still cached by the guest; pause writes, quiesce the application, unmount the data volume or stop an instance whose root volume is being captured when the response plan permits it.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

Do not describe EBS snapshots as files that can simply be copied to S3. To reconstruct the block image without creating a volume, enumerate allocated blocks with `ListSnapshotBlocks`, fetch each 512 KiB block with `GetSnapshotBlock`, validate the returned checksum and zero-fill block indexes that are absent from the sparse snapshot.<sup>[[14]](#references)</sup>

For Azure, create the snapshot, issue a short-lived **read-only** SAS, download the VHD, revoke access and hash the result. Snapshot each disk independently unless the collection mechanism provides coordinated consistency.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Mount

### Treat images as hostile input

A malicious filesystem can target host kernel partition and filesystem parsers. QEMU explicitly warns against connecting an untrusted guest image to host NBD for mounting, and libguestfs recommends never mounting an untrusted guest filesystem directly with loop or `kpartx`.<sup>[[2]](#references)[[16]](#references)</sup>

Prefer `guestmount` for an unknown or attacker-controlled image. It parses and mounts the guest inside a small appliance, then exposes files through FUSE. Force the known format instead of auto-detection and keep the appliance side read-only.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

If inspection cannot infer the OS, replace `-i` with an explicit guest device such as `-m /dev/sda2`. Encrypted LUKS volumes can be supplied with `--key` selectors; avoid putting a key directly in shell history.<sup>[[17]](#references)</sup>

### Choosing a direct host mount

Use a direct host mount only for trusted images or in a disposable analysis VM:

1. Mount the **whole disk** when you need its original partition table.
2. Mount a **single partition image** when you only need one volume.
3. Make the attachment read-only and force the image format. Mount the filesystem read-only too. `ro` alone does not stop ext3/ext4 journal replay, so use `ro,noload` for dirty ext filesystems.<sup>[[2]](#references)[[3]](#references)</sup>

`mmls` is useful when the sector size is not 512 bytes or partition metadata is damaged; `-b` supplies the actual device-sector size. Continue partition and filesystem analysis here:<sup>[[18]](#references)</sup>

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

Detach when finished:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

For qcow2, VMDK or VHD/VHDX, establish the format from trusted provenance or inspect it inside the disposable analysis VM, then replace `--format=raw` with the explicit format. Never rely on host-side format auto-detection for untrusted input.<sup>[[2]](#references)</sup>

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

For filesystem-specific no-replay mounts, ext3/ext4 use `noload`, while XFS uses `norecovery` and requires read-only mode.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` can expose a virtual raw view, but that view still contains the original partition table. Feed it into the same `mmls`, isolated `guestmount` or read-only NBD workflow instead of mounting the whole-disk file as a filesystem.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### BitLocker volumes

Use read-only mode at both layers. `-u` without a value prompts for the password, which avoids placing it in process arguments or shell history.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

For LUKS or LVM, prefer `guestmount -i --ro`; its appliance can inspect common encrypted and logical-volume layouts without activating a foreign volume group on the host.<sup>[[17]](#references)</sup>

### kpartx helpers

`kpartx` creates host device-mapper nodes and therefore is not appropriate for hostile images. When direct mapping is justified, add `-r` so the partition mappings are read-only and remove mappings by passing the same image path used to create them.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Common mount errors & fixes

| Error | Typical cause | Safe next step |
|-------|---------------|----------------|
| `cannot mount ... read-only` | Dirty journaled filesystem | use the filesystem-specific no-replay option such as ext4 `ro,noload` |
| `bad superblock ...` | Wrong partition/sector offset or damaged filesystem | confirm sector size and offset with `mmls`; run `fsck -n` only on a verified copy |
| `unknown filesystem type 'LVM2_member'` | The selected partition is an LVM physical volume | let libguestfs inspect it, or isolate manual LVM activation in a disposable VM |

### Clean-up

Unmount filesystems before disconnecting their backing devices. Also remove the FUSE layer for EWF/xmount and any crypt or device-mapper mappings that were created:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [AFF4 Standard Specification (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd documentation](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [mount(8) Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [The SGI XFS filesystem (Linux kernel documentation)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [SWGDE Best Practices for Digital Evidence Collection](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [SWGDE Best Practices for Computer Forensic Acquisitions](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [dc3dd(1) manual page](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Guymager homepage and configuration documentation](https://guymager.sourceforge.io/)
- [9] [c-aff4 documentation](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Exterro FTK Imager formats and verification](https://www.exterro.com/digital-forensics-software)
- [11] [libewf ewfacquire(1) manual](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [libewf ewfverify(1) manual](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Create Amazon EBS snapshots](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Read Amazon EBS snapshots with EBS direct APIs](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Azure CLI snapshot reference](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [libguestfs security](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
