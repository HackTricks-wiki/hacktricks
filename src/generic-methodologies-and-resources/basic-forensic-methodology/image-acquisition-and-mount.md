# Thu thập ảnh & Gắn kết

{{#include ../../banners/hacktricks-training.md}}

## Thu thập

> Luôn thu thập ở chế độ **chỉ đọc** và **tính hash trong khi sao chép**. Giữ thiết bị gốc ở trạng thái **chặn ghi** và chỉ làm việc trên các bản sao đã được xác minh.

Ghi lại nhà sản xuất, model, số serial và dung lượng của nguồn, công cụ và phiên bản, dấu thời gian, người thực hiện, đích lưu trữ, lỗi và hash thu thập/xác minh. Bảo toàn một ảnh lưu trữ và kiểm tra một bản sao làm việc riêng.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` bổ sung tính năng hash trực tiếp, xác minh đầu ra, ghi nhật ký lỗi và chia đầu ra cho quy trình làm việc của `dd`. `hof=` chọn đầu ra được xác minh bằng hash; `hash=`, `hlog=`, `log=` và `bufsz=` là các toán hạng riêng biệt.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager là công cụ tạo ảnh đĩa Linux có giao diện đồ họa, đa luồng, hỗ trợ đầu ra raw/dd, EWF và AFF cũ. **AFF và AFF4 là hai định dạng khác nhau**; Guymager không quảng cáo hỗ trợ đầu ra AFF4. Bật SHA-256 cùng tính năng xác minh đích trong hộp thoại thu thập dữ liệu, sau đó khởi chạy bằng `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

Đặc tả AFF4 v1.0 định nghĩa một container pháp chứng với khả năng lưu trữ ảo hóa, siêu dữ liệu tùy ý, khả năng nén và băm mở rộng, cùng hiệu suất xử lý cao.<sup>[[1]](#references)</sup>

Bản triển khai C/C++ chuẩn dùng `-i` cho nguồn và `-o` cho volume AFF4. Tạo và lưu giữ một hash container bên ngoài làm cơ sở đối chiếu khi thu thập dữ liệu.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

Tài liệu FTK Imager hiện tại quảng bá các định dạng đầu ra raw/DD, E01 và AFF kèm xác minh hash. Không gọi đầu ra AFF của công cụ này là AFF4.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### Công cụ EWF (libewf)

Để thu thập không cần giám sát, đích được chỉ định bằng `-t`, siêu dữ liệu vụ việc dùng `-C/-D/-E/-e`, `-d sha256` bổ sung SHA-256, còn `-l` ghi lại lỗi thu thập và các giá trị băm. Hãy xác minh toàn bộ tập phân đoạn trước khi phân tích.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Tạo image ổ đĩa cloud

Snapshot của nhà cung cấp là nguồn thu thập tại một thời điểm, không mặc nhiên là forensic image nhất quán với ứng dụng. Snapshot EBS không bao gồm dữ liệu vẫn còn trong bộ nhớ đệm của guest; hãy tạm dừng ghi, đưa ứng dụng về trạng thái ổn định, tháo volume dữ liệu hoặc dừng instance có root volume đang được thu thập nếu kế hoạch ứng phó cho phép.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

Không mô tả EBS snapshot như các tệp có thể đơn giản sao chép sang S3. Để tái tạo block image mà không tạo volume, hãy liệt kê các block đã cấp phát bằng `ListSnapshotBlocks`, tải từng block 512 KiB bằng `GetSnapshotBlock`, xác thực checksum được trả về và điền các block vắng mặt trong sparse snapshot bằng dữ liệu 0.<sup>[[14]](#references)</sup>

Với Azure, hãy tạo snapshot, cấp SAS **chỉ đọc** có thời hạn ngắn, tải VHD xuống, thu hồi quyền truy cập và tính hash cho kết quả. Chụp snapshot từng disk riêng biệt, trừ khi cơ chế thu thập đảm bảo tính nhất quán đồng bộ.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Gắn kết

### Coi image là đầu vào độc hại

Một filesystem độc hại có thể nhắm vào các bộ phân tích phân vùng và filesystem của kernel trên host. QEMU cảnh báo rõ ràng không kết nối image guest không đáng tin cậy với NBD trên host để gắn kết, còn libguestfs khuyến nghị tuyệt đối không gắn kết trực tiếp filesystem guest không đáng tin cậy bằng loop hoặc `kpartx`.<sup>[[2]](#references)[[16]](#references)</sup>

Ưu tiên dùng `guestmount` với image không rõ nguồn gốc hoặc do kẻ tấn công kiểm soát. Công cụ này phân tích và gắn kết guest bên trong một appliance nhỏ, sau đó hiển thị các tệp thông qua FUSE. Hãy chỉ định định dạng đã biết thay vì tự động phát hiện, đồng thời giữ phía appliance ở chế độ chỉ đọc.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

Nếu quá trình kiểm tra không xác định được OS, hãy thay `-i` bằng một thiết bị guest cụ thể, chẳng hạn `-m /dev/sda2`. Có thể cung cấp các volume LUKS đã mã hóa bằng selector `--key`; tránh đưa key trực tiếp vào shell history.<sup>[[17]](#references)</sup>

### Chọn mount trực tiếp trên host

Chỉ dùng mount trực tiếp trên host với image đáng tin cậy hoặc trong một VM phân tích dùng một lần:

1. Mount **toàn bộ đĩa** khi bạn cần bảng phân vùng gốc.
2. Mount **image của một phân vùng** khi bạn chỉ cần một volume.
3. Đặt attachment ở chế độ chỉ đọc và chỉ định rõ định dạng image. Đồng thời mount filesystem ở chế độ chỉ đọc. Chỉ dùng `ro` sẽ không ngăn việc phát lại journal của ext3/ext4, vì vậy hãy dùng `ro,noload` cho các filesystem ext chưa được đánh dấu clean.<sup>[[2]](#references)[[3]](#references)</sup>

`mmls` hữu ích khi kích thước sector không phải 512 byte hoặc metadata phân vùng bị hỏng; `-b` chỉ định kích thước sector thực của thiết bị. Tiếp tục phân tích phân vùng và filesystem tại đây:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Image raw (dd, trích xuất từ AFF4)

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

Tháo ra khi hoàn tất:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

Với qcow2, VMDK hoặc VHD/VHDX, hãy xác định định dạng dựa trên nguồn gốc đáng tin cậy hoặc kiểm tra bên trong máy ảo phân tích dùng một lần, sau đó thay `--format=raw` bằng định dạng cụ thể. Không bao giờ dựa vào tính năng tự động phát hiện định dạng phía host đối với dữ liệu đầu vào không đáng tin cậy.<sup>[[2]](#references)</sup>

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

Đối với các tùy chọn mount không phát lại dành riêng cho từng filesystem, ext3/ext4 dùng `noload`, còn XFS dùng `norecovery` và yêu cầu chế độ chỉ đọc.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` có thể hiển thị một chế độ xem raw ảo, nhưng chế độ xem đó vẫn chứa bảng phân vùng gốc. Hãy đưa nó vào cùng quy trình `mmls`, `guestmount` cách ly hoặc NBD chỉ đọc, thay vì mount tệp toàn bộ đĩa như một filesystem.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### Các volume BitLocker

Sử dụng chế độ chỉ đọc ở cả hai lớp. `-u` không có giá trị sẽ nhắc nhập mật khẩu, tránh để mật khẩu xuất hiện trong đối số tiến trình hoặc lịch sử shell.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

Với LUKS hoặc LVM, hãy ưu tiên `guestmount -i --ro`; appliance của công cụ này có thể kiểm tra các bố cục mã hóa và logical volume phổ biến mà không kích hoạt volume group lạ trên host.<sup>[[17]](#references)</sup>

### Tiện ích hỗ trợ kpartx

`kpartx` tạo các node device-mapper trên host nên không phù hợp với image không đáng tin cậy. Khi có lý do chính đáng để ánh xạ trực tiếp, hãy thêm `-r` để các ánh xạ phân vùng ở chế độ chỉ đọc và xóa các ánh xạ bằng cách truyền vào cùng đường dẫn image đã dùng để tạo chúng.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Các lỗi mount thường gặp và cách khắc phục

| Lỗi | Nguyên nhân thường gặp | Bước tiếp theo an toàn |
|-------|---------------|----------------|
| `cannot mount ... read-only` | Hệ thống tệp có journal chưa được làm sạch | dùng tùy chọn không phát lại journal dành riêng cho hệ thống tệp, chẳng hạn `ro,noload` của ext4 |
| `bad superblock ...` | Sai phân vùng/độ lệch sector hoặc hệ thống tệp bị hỏng | xác nhận kích thước sector và độ lệch bằng `mmls`; chỉ chạy `fsck -n` trên bản sao đã xác minh |
| `unknown filesystem type 'LVM2_member'` | Phân vùng được chọn là một physical volume của LVM | để libguestfs kiểm tra, hoặc cô lập việc kích hoạt LVM thủ công trong một VM dùng một lần |

### Dọn dẹp

Ngắt mount các hệ thống tệp trước khi ngắt kết nối thiết bị lưu trữ nền. Đồng thời gỡ bỏ lớp FUSE dành cho EWF/xmount và mọi ánh xạ crypt hoặc device-mapper đã tạo:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [Đặc tả tiêu chuẩn AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Tài liệu QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Trang hướng dẫn Linux mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Hệ thống tệp SGI XFS (tài liệu Linux kernel)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [Các phương pháp hay nhất của SWGDE về thu thập bằng chứng số](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [Các phương pháp hay nhất của SWGDE về thu thập dữ liệu máy tính forensics](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [Trang hướng dẫn dc3dd(1)](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Trang chủ Guymager và tài liệu cấu hình](https://guymager.sourceforge.io/)
- [9] [Tài liệu c-aff4](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Các định dạng và xác minh của Exterro FTK Imager](https://www.exterro.com/digital-forensics-software)
- [11] [Trang hướng dẫn libewf ewfacquire(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [Trang hướng dẫn libewf ewfverify(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Tạo Amazon EBS snapshots](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Đọc Amazon EBS snapshots bằng EBS direct APIs](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Tham chiếu snapshot của Azure CLI](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [Bảo mật libguestfs](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
