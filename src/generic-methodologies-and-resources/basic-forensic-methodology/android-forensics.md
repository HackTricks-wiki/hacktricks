# Điều tra pháp chứng Android

{{#include ../../banners/hacktricks-training.md}}

## Thiết bị bị khóa

Ưu tiên các phương pháp thu thập dữ liệu giúp giữ nguyên trạng thái thiết bị và ghi lại mọi thao tác. Nếu thiết bị bị khóa, các lựa chọn khả dụng phụ thuộc vào model, phiên bản Android, cấp độ bản vá và việc quyền truy cập đã được thiết lập trước khi thu giữ hay chưa. NIST khuyến nghị chọn phương pháp phù hợp với thiết bị và thẩm quyền tiến hành kiểm tra.<sup>[[1]](#references)</sup>

- Kiểm tra xem USB debugging đã được bật chưa và máy trạm thu thập dữ liệu đã được cấp quyền hay chưa. Để truy cập ADB, thông thường người dùng phải mở khóa thiết bị và xác nhận khóa RSA của máy trạm.<sup>[[3]](#references)</sup>
- Cân nhắc xem quyền truy cập bằng sinh trắc học có còn khả dụng theo các quy định pháp lý và thủ tục áp dụng hay không.
- **Smudge attack** có thể giúp xác định hình mở khóa từ vết bẩn còn lại trên màn hình, dù các lần chạm sau đó và việc lau màn hình sẽ làm giảm độ tin cậy của phương pháp này.<sup>[[2]](#references)</sup>
- Nếu công cụ được cấp phép hỗ trợ chính xác thiết bị và bản dựng phần mềm, công cụ có thể thử khôi phục hoặc brute force PIN, mật khẩu hay hình mở khóa. Cơ chế xác minh thông tin xác thực dựa trên phần cứng, thời gian chờ giữa các lần thử và chính sách xóa dữ liệu khiến phương pháp này phụ thuộc nhiều vào từng thiết bị. Vì vậy, không được lấy kỹ thuật hay kết quả trên iPhone làm bằng chứng rằng thiết bị Android được hỗ trợ.<sup>[[1]](#references)</sup>

## Thu thập dữ liệu

Trên các thiết bị đời cũ, [ADB backup](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) cũ có thể tạo tệp `.backup` mà Android Backup Extractor có thể giải nén:<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

Không nên giả định rằng cách này thu thập được dữ liệu của mọi ứng dụng. ADB đánh dấu lệnh này là deprecated, và Android 12 loại trừ dữ liệu của các ứng dụng nhắm đến API level 31 trở lên, trừ khi ứng dụng có thể debug được.<sup>[[4]](#references)</sup>

### Quyền root hoặc quyền truy cập debug vật lý

Khi có quyền root trên thiết bị đang hoạt động, trước tiên hãy kiểm kê các phân vùng và điểm gắn kết; các lệnh bên dưới không áp dụng trực tiếp cho việc thu thập dữ liệu JTAG vật lý. Thiết bị khối chính xác phụ thuộc vào phần cứng, vì vậy đừng mặc định rằng nó luôn là `mmcblk0`. Chỉ tạo ảnh từ nguồn đã được xác minh sang thiết bị lưu trữ riêng:<sup>[[1]](#references)</sup>

Thay vào đó, việc thu thập dữ liệu JTAG sử dụng giao diện truy cập kiểm thử phần cứng của thiết bị và thiết bị thu thập dữ liệu tương thích để đọc bộ nhớ có thể truy cập. Sơ đồ chân, khả năng hỗ trợ chipset, trạng thái thiết bị và sự khác biệt giữa mục tiêu lưu trữ khả biến và bất biến phụ thuộc vào từng thiết bị; hãy ghi lại đường kết nối phần cứng và sử dụng quy trình đã được kiểm chứng cho mẫu thiết bị đó.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

Ví dụ, nếu danh mục phân vùng xác nhận rằng `/dev/block/mmcblk0` là toàn bộ thiết bị flash và đích có đủ dung lượng, lệnh thu thập dữ liệu ban đầu trở thành:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

Ở đây, `df /data` giúp xác định `/data` thuộc hệ thống tệp nào được gắn kết; không nên xem đây là bằng chứng cho thấy `mmcblk0` là nguồn toàn thiết bị chính xác hoặc `4096` là kích thước khối `dd` hợp lệ duy nhất.

Tính hash của kết quả và ghi lại chính xác lệnh, mã định danh thiết bị, thời gian và mọi thay đổi được thực hiện trong quá trình thu thập.<sup>[[1]](#references)</sup>

### Bộ nhớ

LiME có thể thu thập bộ nhớ vật lý từ Linux và một số thiết bị Android, nhưng module kernel của nó phải được biên dịch cho kernel mục tiêu và tải với đủ quyền. Việc ký module, khóa kernel và các cơ chế hardening hiện đại của Android có thể ngăn module được tải.<sup>[[5]](#references)</sup>

Quy trình Android của dự án đẩy module tương thích bằng ADB, chuyển tiếp một cổng TCP, tải module từ root shell và thu thập luồng dữ liệu trên máy chủ phân tích:<sup>[[5]](#references)</sup>

```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```

LiME cũng có thể ghi vào bộ nhớ thiết bị bằng `path=/sdcard/ram.lime`, nhưng việc này làm thay đổi bộ nhớ của thiết bị và cần đủ dung lượng trống. Ghi lại tác động phụ đó và hash image đã thu thập.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Hướng dẫn về pháp chứng thiết bị di động](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Tấn công Smudge trên màn hình cảm ứng điện thoại thông minh](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Hạn chế sao lưu ADB trên Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Trình trích xuất bộ nhớ Linux (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Trình giải nén bản sao lưu Android](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
