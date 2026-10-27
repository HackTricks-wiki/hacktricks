# Dump bộ nhớ macOS

{{#include ../../../banners/hacktricks-training.md}}

## Tạo phẩm bộ nhớ

### Tệp hoán đổi

Các tệp hoán đổi, chẳng hạn như `/private/var/vm/swapfile0`, đóng vai trò là **bộ nhớ đệm khi bộ nhớ vật lý đã đầy**. Khi bộ nhớ vật lý không còn chỗ trống, dữ liệu trong đó được chuyển sang tệp hoán đổi rồi được đưa trở lại bộ nhớ vật lý khi cần. Có thể có nhiều tệp hoán đổi, với tên như swapfile0, swapfile1, v.v.

### Ảnh ngủ đông

Tệp nằm tại `/private/var/vm/sleepimage` rất quan trọng trong **chế độ ngủ đông**. **Dữ liệu từ bộ nhớ được lưu vào tệp này khi OS X chuyển sang chế độ ngủ đông**. Khi máy tính hoạt động trở lại, hệ thống lấy dữ liệu bộ nhớ từ tệp này, cho phép người dùng tiếp tục từ nơi họ đã dừng lại.

Trên các hệ thống macOS hiện đại, tệp này thường được mã hóa, khiến việc khôi phục trở nên khó khăn.

- Để kiểm tra xem sleepimage có được mã hóa hay không, có thể chạy lệnh `sysctl vm.swapusage`. Lệnh này sẽ cho biết tệp có được mã hóa hay không.

### Nhật ký áp lực bộ nhớ

Một tạo phẩm khác liên quan đến bộ nhớ trên macOS là **nhật ký áp lực bộ nhớ**. Các nhật ký này chứa thông tin về mức sử dụng bộ nhớ và các sự kiện áp lực bộ nhớ, đồng thời có thể giúp giải thích cách hệ thống quản lý bộ nhớ theo thời gian. Các bản phát hành cũ có thể lưu những tệp liên quan trong `/var/log`; các bản phát hành hiện tại cũng cung cấp thông tin về áp lực bộ nhớ thông qua unified log và báo cáo chẩn đoán.

## Dump bộ nhớ bằng osxpmem

Để dump bộ nhớ vật lý trên các phiên bản macOS cũ được hỗ trợ, bạn có thể dùng [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Lưu ý**: Hiện nay, đây chủ yếu là một **quy trình cũ**. `osxpmem` cần tải một kernel extension; dự án [Rekall](https://github.com/google/rekall) đã bị lưu trữ, bản phát hành mới nhất là từ **2017**, và binary được phát hành nhắm đến **máy Mac dùng Intel**. Trên các bản macOS hiện tại, đặc biệt là trên **Apple Silicon**, việc thu thập toàn bộ RAM bằng kext thường bị chặn bởi các hạn chế hiện đại đối với kernel extension, SIP và yêu cầu ký nền tảng. Trên thực tế, trên các hệ thống hiện đại, bạn thường sẽ phải thực hiện **dump trong phạm vi một process** thay vì tạo ảnh toàn bộ RAM.

```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```

Nếu gặp lỗi này: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Bạn có thể khắc phục bằng cách:

```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```

**Các lỗi khác** có thể được khắc phục bằng cách **cho phép tải kext** trong "Security & Privacy --> General"; chỉ cần nhấn **Allow**.

Bạn cũng có thể dùng **oneliner** này để tải ứng dụng, tải kext và dump bộ nhớ:

```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```

## Dump bộ nhớ tiến trình đang chạy bằng LLDB

Với **các phiên bản macOS gần đây**, cách thực tế nhất thường là dump bộ nhớ của **một tiến trình cụ thể** thay vì cố gắng tạo ảnh toàn bộ bộ nhớ vật lý.

LLDB có thể lưu tệp core Mach-O từ một tiến trình đang chạy:

```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```

Theo mặc định, thao tác này thường tạo ra một **skinny core**. Để buộc LLDB đưa toàn bộ bộ nhớ đã ánh xạ của tiến trình vào:

```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```

Các lệnh hữu ích cần chạy tiếp trước khi dump:

```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```

Thông thường, như vậy là đủ khi mục tiêu là thu thập:

- Các blob cấu hình đã giải mã
- Token, cookie hoặc thông tin xác thực trong bộ nhớ
- Các bí mật dạng plaintext chỉ được bảo vệ khi lưu trữ
- Các trang Mach-O đã giải mã sau khi unpacking / JIT / vá trong runtime

Nếu mục tiêu được bảo vệ bởi **hardened runtime**, hoặc `taskgated` từ chối attach, bạn thường cần một trong các điều kiện sau:

- Mục tiêu có **`get-task-allow`**
- Debugger của bạn được ký với **debugger entitlement** phù hợp
- Bạn là **root** và mục tiêu là một tiến trình bên thứ ba không dùng hardened runtime

Để biết thêm về cách lấy task port và những gì có thể thực hiện với nó:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Kiểm tra nhanh trước khi attach

Trước khi dành thời gian cho LLDB/Frida, hãy nhanh chóng xác minh xem mục tiêu có thực sự **dump được** hay không:

```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
  egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```

Về mặt vận hành, điều này thường có nghĩa là:

- Ứng dụng bên thứ ba được phát hành kèm **`get-task-allow`** thường có thể dump trực tiếp bằng LLDB, và dump thu được có thể làm lộ dữ liệu được TCC bảo vệ mà ứng dụng đã truy cập.<sup>[[1]](#references)</sup>
- Mục tiêu **hardened** không có `get-task-allow` thường sẽ từ chối các lần attach, ngay cả khi chạy với quyền `root`, trừ khi bạn kiểm soát các entitlements của debugger có liên quan / đường dẫn policy.
- Các tiến trình bên thứ ba không được hardened vẫn là nơi dễ nhất để dùng `lldb`, `vmmap`, Frida hoặc các công cụ đọc `task_for_pid`/`vm_read` tùy chỉnh.

### Tìm các helper lồng nhau có thể dump

Nghiên cứu gần đây về các ứng dụng macOS đã notarize liên tục phát hiện **`get-task-allow` trong các helper lồng nhau** thay vì binary GUI chính. Khi một ứng dụng cấp cao nhất có vẻ đã được hardened, hãy liệt kê **XPC services**, **login items**, **helper tools** và các CLI đi kèm trước khi bỏ cuộc:

```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
  codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```

Một executable lồng bên trong có `get-task-allow` thường là nơi dễ nhất để attach bằng `lldb`, dump core hoặc lấy memory bằng một client `task_for_pid` tự viết, ngay cả khi app chính được harden tốt hơn.

## Selective dumps with Frida or userland readers

Khi core dump đầy nhiễu, chỉ dump các **vùng có thể đọc đáng chú ý** thường nhanh hơn. Frida đặc biệt hữu ích vì hỗ trợ tốt việc **trích xuất có mục tiêu** khi bạn đã có thể attach vào process.

Cách tiếp cận ví dụ:

1. Liệt kê các vùng có quyền đọc/ghi
2. Lọc theo module, heap, stack hoặc memory ẩn danh
3. Chỉ dump các vùng chứa chuỗi, key, protobuf, blob plist/XML hoặc code/data đã giải mã có khả năng đáng chú ý

Ví dụ Frida tối giản để dump mọi vùng ẩn danh có thể đọc:

```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
  try {
    if (range.file) return;
    var dump = range.base.readByteArray(range.size);
    var f = new File('/tmp/' + range.base + '.bin', 'wb');
    f.write(dump);
    f.close();
  } catch (e) {}
});
```

Điều này hữu ích khi bạn muốn tránh tạo các core file khổng lồ và chỉ thu thập:

- Các khối heap của ứng dụng chứa bí mật
- Các vùng ẩn danh được tạo bởi packer hoặc loader tùy chỉnh
- Các trang mã JIT / đã giải nén sau khi thay đổi quyền truy cập

Khi tiến trình mục tiêu vẫn đang **cấp phát / giải phóng bộ nhớ** trong lúc bạn dump, hãy ưu tiên primitive **`readVolatile()`** của Frida thay cho **`readByteArray()`** khi đọc các vùng không ổn định. Primitive này chậm hơn, nhưng tránh làm tiến trình mục tiêu bị dừng nếu một trang trở nên không thể đọc được giữa chừng. Với các lần thu thập dữ liệu lớn hơn, cũng có thể truyền các khối dữ liệu về bằng `send(..., data)` rồi nén chúng ở phía controller, thay vì tạo hàng nghìn tệp nhỏ bên trong tiến trình mục tiêu.

Các công cụ userland cũ hơn như [`readmem`](https://github.com/gdbinit/readmem) cũng tồn tại, nhưng chủ yếu hữu ích làm **tài liệu tham khảo mã nguồn** cho kiểu dump trực tiếp bằng `task_for_pid`/`vm_read` và không được duy trì tốt cho các quy trình làm việc hiện đại trên Apple Silicon.

## Ảnh chụp heap / VM với `.memgraph`

Nếu bạn chủ yếu quan tâm đến **các đối tượng heap**, **nguồn gốc cấp phát** hoặc một ảnh chụp có thể chuyển sang máy khác, thì `.memgraph` thường thực tế hơn một Mach-O core khổng lồ. Công cụ `leaks` có thể tạo ảnh chụp từ một tiến trình đang chạy:<sup>[[2]](#references)</sup>

```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```

Sau đó phân tích nó ngoại tuyến bằng các công cụ tiêu chuẩn của Apple:

```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```

`stringdups` là lý do chính để giữ lại bản capture `-fullContent`, vì các nhãn mô tả nội dung bộ nhớ bị lược bỏ khỏi `.memgraph` tối giản.

Điều này đặc biệt hữu ích khi:

- Bạn muốn một **snapshot nhỏ hơn, dễ chia sẻ** thay vì một core dump đầy đủ
- `MallocStackLogging` đã được bật và bạn muốn xem **allocation backtraces**
- Bạn đã biết một **địa chỉ heap đáng chú ý** và muốn lần theo bằng `malloc_history`
- Bạn cần phân tích nhanh **VM/heap** trước khi quyết định liệu full dump có đáng để tạo thêm nhiễu hay không

### Differential memgraph triage

Nếu bạn kiểm soát cách target khởi chạy, hãy bật **historical allocation logging** trước khi khởi chạy để các snapshot về sau lưu lại những allocation/free backtrace hữu ích:

```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```

Sau đó, hãy chụp snapshot trước và sau hành động đáng chú ý rồi so sánh chúng ngoại tuyến:

```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```

Đây là cách thực tế để cô lập **các object hậu xác thực**, **các buffer `CFData` lớn** hoặc **các vùng VM ẩn danh** chỉ xuất hiện sau giai đoạn giải mã, giải đóng gói hoặc truy xuất bí mật.

## Mục tiêu sử dụng nhiều Swift: `swift-inspect`

Đối với các ứng dụng lưu dữ liệu giá trị cao bên trong **các object runtime của Swift**, `swift-inspect` có thể bổ trợ hiệu quả cho LLDB hoặc Frida. Thay vì dump mọi thứ trước, bạn có thể truy vấn các cấu trúc runtime cụ thể của Swift từ một process đang chạy:

```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```

Điều này hữu ích để xác định:

- Các mảng Swift lớn đang đệm dữ liệu đáng chú ý
- Các vùng cấp phát metadata tiết lộ những kiểu dữ liệu được tải lúc runtime
- Trạng thái đồng thời của Swift (`Task`, actor, các mối quan hệ giữa thread) trước khi thực hiện dump có mục tiêu cụ thể hơn

Để phân loại nhanh ở cấp đối tượng khi đã có thể kiểm tra process, hãy xem [trang chuyên biệt về các đối tượng trong bộ nhớ](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Ghi chú phân loại nhanh

- `sysctl vm.swapusage` vẫn là cách nhanh để kiểm tra **mức sử dụng swap** và liệu swap có được **mã hóa** hay không.
- `sleepimage` vẫn chủ yếu liên quan đến các tình huống **hibernate/safe sleep**, nhưng các hệ thống hiện đại thường bảo vệ nó; vì vậy, nên xem đây là **nguồn artifact cần kiểm tra**, chứ không phải một phương thức thu thập đáng tin cậy.
- Trên các phiên bản macOS gần đây, **dump ở cấp process** thường khả thi hơn **tạo ảnh toàn bộ bộ nhớ vật lý**, trừ khi bạn kiểm soát chính sách khởi động, trạng thái SIP và việc tải kext.

## References

- [1] [Cho phép hay không cho phép get-task-allow: Phân tích bảo mật macOS](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [Trang hướng dẫn man của leaks(1)](https://keith.github.io/xcode-man-pages/leaks.1.html)
{{#include ../../../banners/hacktricks-training.md}}
