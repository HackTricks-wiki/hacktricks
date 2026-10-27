# Open vSwitch loại bỏ marker của skb được chuyển tiếp, dẫn đến ghi vào page-cache qua ESP

{{#include ../../../banners/hacktricks-training.md}}

Một kỹ thuật khai thác kernel Linux hữu ích là **loại bỏ metadata về quyền sở hữu khỏi skb mà không xóa các fragment ngoại lai của nó**, rồi chuyển skb đó đến một thành phần ghi dữ liệu trực tiếp. Trong trường hợp Open vSwitch (OVS), một lần upcall lên userspace thất bại sẽ xóa `SKBFL_SHARED_FRAG` khỏi skb `MSG_ZEROCOPY` vẫn còn hoạt động; sau đó, ESP giải mã trực tiếp lên folio page-cache của một file chỉ đọc. Cách này cho phép ghi cục bộ có thể dự đoán vào page-cache và đã được theo dõi qua các CVE-2026-90049, CVE-2026-89487 và CVE-2026-80977.<sup>[[1]](#references)[[2]](#references)</sup>

Đây là vấn đề thuộc nhóm Copy Fail/Dirty Frag, không phải lỗi hỏng bộ nhớ kiểu cổ điển: không cần race hay lộ địa chỉ, chỉ cần file có thể đọc được, và các byte bị thay đổi nằm trong page-cache chứ không phải trên đĩa.<sup>[[2]](#references)[[3]](#references)</sup>

## Bất biến bảo mật: các fragment ngoại lai phải luôn được đánh dấu

`SKBFL_SHARED_FRAG` báo cho các thành phần ghi trực tiếp rằng một fragment của skb có thể tham chiếu đến vùng lưu trữ mà chúng không sở hữu riêng. Fast path ESP trong `esp_input()` chỉ có thể giải mã tại chỗ một skb phi tuyến tính, chưa được clone nếu `skb_has_shared_frag()` trả về false; nếu không, `skb_cow_data()` sẽ tạo vùng lưu trữ riêng trước. Kiểm tra phía consumer này được bổ sung sau Dirty Frag.<sup>[[5]](#references)</sup>

Do đó, bất biến này gồm hai phần độc lập:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. Các thành phần ghi trực tiếp phải kiểm tra `SKBFL_SHARED_FRAG` và sao chép dữ liệu dùng chung trước khi sửa đổi.
2. Mọi đường dẫn clone, coalesce, chuyển giao hoặc chuyển tiếp phải giữ nguyên marker chừng nào page ngoại lai vẫn còn được gắn vào skb.

Fragnesia vi phạm quy tắc thứ hai khi di chuyển các fragment descriptor trong `skb_try_coalesce()`. Đường dẫn OVS có khác biệt tinh vi: nó không chuyển fragment đi; thay vào đó, nó xóa marker **ngay trên skb gốc rồi tiếp tục chuyển tiếp skb đó**.<sup>[[2]](#references)[[4]](#references)</sup>

## Khả năng tiếp cận OVS không cần đặc quyền

Datapath kernel của OVS được điều khiển thông qua các họ generic-netlink như `ovs_datapath`, `ovs_vport`, `ovs_flow` và `ovs_packet`. Các thao tác làm thay đổi trạng thái sử dụng `GENL_UNS_ADMIN_PERM` có xét đến namespace, nên một tiến trình chạy trong `unshare -Urn` sẽ có `CAP_NET_ADMIN` cần thiết để tạo datapath, gắn một veth và cài đặt các flow action bên trong network namespace của chính nó. Việc phân giải họ OVS cũng có thể tự động nạp `openvswitch.ko`; cuộc tấn công này không yêu cầu `CAP_SYS_MODULE` trên host, `ovs-vsctl` hay `ovs-vswitchd`.<sup>[[2]](#references)[[7]](#references)</sup>

Điểm khác biệt quan trọng nằm ở hai loại upcall:<sup>[[2]](#references)[[7]](#references)</sup>

- **Flow miss** gửi packet đến `ovs-vswitchd`; nếu upcall thất bại, packet thường bị drop.
- Action `OVS_ACTION_ATTR_USERSPACE` tường minh gửi một bản sao được mượn đến port ID được chọn, rồi thực thi các action tiếp theo trên skb gốc.

Do đó, kẻ tấn công có thể cài đặt một flow có cấu trúc như sau:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

Không có listener nào sở hữu port ID đã chọn, khiến hành động userspace thất bại một cách có thể dự đoán, trong khi hành động `OUTPUT` tiếp theo giữ cho packet ban đầu vẫn tồn tại.<sup>[[1]](#references)[[2]](#references)</sup>

## Nguyên nhân gốc: `skb_tx_error()` trên một packet vẫn tồn tại

Đường dẫn lỗi upcall OVS dễ bị tấn công gọi `skb_tx_error(skb)`. Helper đó được thiết kế cho trường hợp truyền tải thất bại, sau đó skb được giải phóng; nó hoàn tất việc quản lý zerocopy thông qua `skb_zcopy_clear()`, mà theo lịch sử, mask cờ của hàm này cũng xóa `SKBFL_SHARED_FRAG`. OVS bỏ qua lỗi của userspace action và tiếp tục danh sách action, vi phạm hợp đồng về vòng đời của helper.<sup>[[1]](#references)[[2]](#references)</sup>

Chuyển đổi trạng thái có thể khai thác là:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

Điều này chỉ hoạt động khi `skb_zcopy()` tìm thấy trạng thái zerocopy. Một fragment chỉ mang `SKBFL_SHARED_FRAG` là chưa đủ; `MSG_ZEROCOPY` hữu ích vì nó tạo `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` và cũng đặt `SKBFL_DONT_ORPHAN`. Cờ sau khiến `skb_orphan_frags()` bỏ qua việc thay thế các page ngoại lai trong quá trình OVS sao chép dữ liệu sang userspace.<sup>[[2]](#references)[[3]](#references)</sup>

## Xây dựng primitive ghi

Trigger đầu-cuối bao gồm các thành phần sau.<sup>[[2]](#references)[[3]](#references)</sup>

1. Vào các user namespace và network namespace riêng bằng `unshare -Urn`.
2. Map một tệp đích có thể đọc bằng `PROT_READ | MAP_SHARED`.
3. Dùng một sender netns riêng và một cặp veth; loopback cục bộ sẽ sao chép các page mượn và phá hủy primitive này.
4. Tạo một OVS datapath cùng flow `USERSPACE`-rồi-`OUTPUT` gây lỗi.
5. Cài đặt trạng thái XFRM ESP-in-UDP ở transport mode bằng `rfc4106(gcm(aes))` và cổng UDP 4500.
6. Gửi một datagram `MSG_ZEROCOPY` với iovec có cấu trúc `[ESP header | mapped file bytes | invalid ICV]`.

Trạng thái XFRM sử dụng 20 byte vật liệu khóa AES-128-GCM: 16 byte khóa AES, theo sau là salt RFC 4106 gồm bốn byte. Với một IV tường minh dài tám byte được chọn trước, tính bảo mật của payload bắt đầu bằng khối bộ đếm `salt || IV || be32(2)`; giá trị bộ đếm 1 thay vào đó sẽ che kết quả xác thực.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

Sau khi OVS loại bỏ marker, ESP đi theo nhánh no-copy và thực hiện `plaintext = ciphertext XOR keystream` trên fragment được hỗ trợ bởi file. Việc xác thực được kiểm tra **sau** phép biến đổi này, vì vậy ICV không hợp lệ gồm toàn số 0 khiến packet thất bại với `-EBADMSG` chỉ sau khi các byte trong page cache đã bị thay đổi.<sup>[[2]](#references)</sup>

### Chuyển GCM thành các byte tùy chọn

Với byte hiện tại `C` và byte mong muốn `P`, byte đầu tiên của keystream payload phải là `C XOR P`. Khi AES key và salt được cố định, hãy quét một hậu tố 16-bit của explicit IV và tính trước một hậu tố cho mỗi byte keystream đầu tiên có thể có:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

Bản triển khai công khai giới hạn ciphertext ở 32 byte và dịch fragment của file đi một byte cho mỗi packet. Byte đầu tiên đã chọn sẽ ghi đè byte collateral đầu tiên của packet trước; `pread()` làm mới `C` trước mỗi packet, các byte trùng nhau sẽ được bỏ qua, và packet cuối được rút ngắn để thao tác ghi không vượt quá phạm vi yêu cầu. Vì vậy, bảng tra cứu 256 phần tử biến primitive này thành thao tác ghi page cache theo từng byte với nội dung tùy chọn, chỉ cần khoảng một packet cho mỗi byte khác nhau.<sup>[[2]](#references)[[3]](#references)</sup>

## Ghi page cache để chiếm quyền root

Một mục tiêu thực tế là một executable setuid-root có sẵn. PoC thay thế 160 byte đầu tiên bằng một ELF tĩnh hoàn chỉnh, chứa một `PT_LOAD` có địa chỉ cố định với quyền đọc/thực thi, không có `PT_INTERP`, và mã gọi `setuid(0)` trước khi gọi `execve("/bin/sh", ...)`. Cách này tránh phải dựa vào entry point, bố cục PIE, dynamic loader hoặc relocations của binary ban đầu.<sup>[[2]](#references)[[3]](#references)</sup>

Thay đổi này hiển thị trên mọi user namespace vì page cache không được namespace hóa. Folio đã bị thay đổi không được đánh dấu dirty, nên sẽ không được ghi ngược ra đĩa; hãy thực thi mục tiêu khi nó còn trong bộ nhớ, sau đó loại bỏ phần dữ liệu tạm thời bị làm hỏng bằng `posix_fadvise(..., POSIX_FADV_DONTNEED)` để các lần đọc sau nạp lại nội dung ban đầu trên đĩa.<sup>[[2]](#references)[[3]](#references)</sup>

## Kiểm tra mức độ phơi nhiễm và giảm thiểu

Trước tiên, hãy kiểm tra kernel thực tế của nhà cung cấp. Các điều kiện liên quan đến mức độ phơi nhiễm gồm user namespace không đặc quyền, OVS khả dụng hoặc đang hoạt động, và có triển khai ESP khả dụng.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Nâng cấp lên kernel có đầy đủ chuỗi bản sửa; bản sửa cuối cùng khắc phục đường recirculation và tránh sửa đổi trạng thái `skb_shinfo()` dùng chung, đồng thời xử lý một lỗi strip liên quan trong `skb_zerocopy()`.<sup>[[1]](#references)[[2]](#references)</sup>

Nếu không dùng OVS, hãy ngăn việc tải module cả bằng alias lẫn theo tên bằng quy tắc `install` của modprobe, thay vì chỉ dựa vào `blacklist`. Nếu máy chủ không kết thúc IPsec và ESP là module, biện pháp tương tự có thể loại bỏ decrypt sink.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

Các quy tắc này không có tác dụng khi module đã được tải hoặc tính năng được tích hợp sẵn vào kernel. Việc tắt unprivileged user namespaces cũng loại bỏ nguồn cấp namespace capability, nhưng có thể làm hỏng trình duyệt, Flatpak, Podman và các workload sandbox/container khác.<sup>[[2]](#references)</sup>

## Review lessons

Khi audit mạng zero-copy, đừng chỉ tìm các helper sao chép hoặc di chuyển fragment. Hãy xác định cả các helper xử lý lỗi/hoàn tất có xóa các cờ được nhóm chung hay không, rồi xác minh rằng mọi caller đều tuân thủ hợp đồng về vòng đời skb đã được tài liệu hóa. Một bit biểu thị quyền sở hữu page được nhóm với các bit vòng đời zerocopy là yếu tố nhạy cảm về bảo mật, ngay cả khi đoạn mã xóa bit không trực tiếp truy cập fragment nào.<sup>[[1]](#references)[[2]](#references)</sup>

Một bản sửa lỗi vững chắc phải bao quát mọi đường đi khiến skb có thể tồn tại—bao gồm cả action continuation và recirculation—đồng thời tính đến các clone dùng chung `skb_shinfo()`. Ở phía consumer, lỗi xác thực không hoàn tác các lần ghi plaintext đã được thực hiện bởi phép biến đổi AEAD tại chỗ, vì vậy cần kiểm tra foreign-storage trước khi bắt đầu giải mã.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Loạt bản sửa lỗi netdev của Doyensec: net: không xóa dấu frag zerocopy khỏi skb được forward](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: Việc xóa dấu Forwarded-SKB trong Open vSwitch cho phép LPE page-cache ESP có thể tái hiện một cách xác định](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Proof of concept `ovs-pagecache-write` của Doyensec](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Bản sửa lỗi Linux cho đường coalescing Fragnesia ban đầu (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Kiểm tra shared-fragment phía consumer ESP trong Linux (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: Việc sử dụng Galois/Counter Mode (GCM) trong IPsec ESP](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Tài liệu kernel datapath của Open vSwitch](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
