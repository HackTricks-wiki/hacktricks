# Ràng buộc Launch/Environment trên macOS & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

Ràng buộc launch trên macOS được giới thiệu nhằm tăng cường bảo mật bằng cách **quy định một process có thể được khởi chạy như thế nào, bởi ai và từ đâu**. Được giới thiệu trong macOS Ventura, chúng cung cấp một framework phân loại **từng binary hệ thống thành các nhóm ràng buộc riêng biệt** được định nghĩa trong **trust cache**, một danh sách chứa các binary hệ thống và hash tương ứng của chúng. Các ràng buộc này áp dụng cho mọi executable binary trong hệ thống, bao gồm một tập hợp **quy tắc** quy định yêu cầu để **khởi chạy một binary cụ thể**. Các quy tắc bao gồm self constraint mà binary phải đáp ứng, parent constraint mà process cha của nó phải đáp ứng, và responsible constraint mà các thực thể liên quan khác phải tuân thủ.<sup>[[1]](#references)[[4]](#references)</sup>

Cơ chế này được mở rộng cho các ứng dụng bên thứ ba từ macOS Sonoma, thông qua **Environment Constraints**, cho phép developer bảo vệ ứng dụng bằng cách chỉ định **một tập hợp các khóa và giá trị cho environment constraint.**<sup>[[5]](#references)</sup>

Bạn định nghĩa **ràng buộc launch environment và library** trong các constraint dictionary, sau đó lưu chúng trong **tệp property list của `launchd`** hoặc trong các tệp **property list riêng biệt** được sử dụng khi ký code.<sup>[[5]](#references)</sup>

Có 4 loại ràng buộc:

- **Self Constraints**: Ràng buộc áp dụng cho binary **đang chạy**.
- **Parent Process**: Ràng buộc áp dụng cho **process cha của process** (ví dụ: **`launchd`** chạy một dịch vụ XP)
- **Responsible Constraints**: Ràng buộc áp dụng cho **process gọi dịch vụ** trong giao tiếp XPC
- **Library load constraints**: Dùng library load constraint để mô tả có chọn lọc code có thể được tải

Vì vậy, khi một process cố khởi chạy một process khác — bằng cách gọi `execve(_:_:_:)` hoặc `posix_spawn(_:_:_:_:_:_:)` — hệ điều hành kiểm tra xem tệp **executable** có **đáp ứng** **self constraint của chính nó** hay không. Hệ điều hành cũng kiểm tra xem executable của **process cha** có **đáp ứng parent constraint** của executable đó hay không, và executable của **responsible process** có **đáp ứng responsible process constraint của executable** hay không. Nếu bất kỳ launch constraint nào không được đáp ứng, hệ điều hành sẽ không chạy chương trình.

Nếu bất kỳ phần nào của **library constraint không đúng** khi tải một library, process của bạn **sẽ không tải** library đó.

## Các nhóm LC

Một LC được cấu thành từ **các fact** và **các phép toán logic** (and, or, v.v.) kết hợp các fact.

[Các **fact mà một LC có thể sử dụng được ghi trong tài liệu**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Ví dụ:

- is-init-proc: Giá trị Boolean cho biết executable có phải là process khởi tạo của hệ điều hành (`launchd`) hay không.
- is-sip-protected: Giá trị Boolean cho biết executable có phải là tệp được System Integrity Protection (SIP) bảo vệ hay không.
- `on-authorized-authapfs-volume:` Giá trị Boolean cho biết hệ điều hành có tải executable từ một volume APFS được ủy quyền và xác thực hay không.
- `on-authorized-authapfs-volume`: Giá trị Boolean cho biết hệ điều hành có tải executable từ một volume APFS được ủy quyền và xác thực hay không.
  - Volume Cryptexes
- `on-system-volume:` Giá trị Boolean cho biết hệ điều hành có tải executable từ system volume đang được khởi động hay không.
  - Bên trong /System...
- ...

Khi một binary của Apple được ký, nó sẽ **được gán vào một nhóm LC** trong **trust cache**.

- Các **nhóm LC của iOS 16** đã được [**reverse và ghi lại tại đây**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Các **nhóm LC hiện tại (macOS 14** - Somona) đã được reverse và [**mô tả có thể tìm thấy tại đây**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Ví dụ, Category 1 là:<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: Phải nằm trong volume System hoặc Cryptexes.
- `launch-type == 1`: Phải là một system service (plist trong LaunchDaemons).
- `validation-category == 1`: Một tệp thực thi của hệ điều hành.
- `is-init-proc`: Launchd

### Phân tích ngược các danh mục LC

Bạn có thể tìm thêm thông tin [**tại đây**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), nhưng về cơ bản, chúng được định nghĩa trong **AMFI (AppleMobileFileIntegrity)**, vì vậy bạn cần tải Kernel Development Kit để lấy **KEXT**. Các symbol bắt đầu bằng **`kConstraintCategory`** là những symbol **đáng chú ý**. Trích xuất chúng sẽ cho bạn một luồng được mã hóa theo DER (ASN.1), cần giải mã bằng [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) hoặc thư viện python-asn1 cùng script `dump.py` của nó, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), để có được chuỗi dễ hiểu hơn.<sup>[[3]](#references)[[8]](#references)</sup>

## Các ràng buộc môi trường

Đây là các Launch Constraints được cấu hình trong **ứng dụng của bên thứ ba**. Nhà phát triển có thể chọn các **fact** và **toán tử logic cần dùng** trong ứng dụng để hạn chế quyền truy cập vào chính ứng dụng đó.

Có thể liệt kê các ràng buộc môi trường của một ứng dụng bằng cách:

```bash
codesign -d -vvvv app.app
```

## Trust Cache

Trong **macOS** có một số trust cache:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Còn trong iOS, trust cache có vẻ nằm ở **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Trên macOS chạy trên thiết bị Apple Silicon, nếu một binary do Apple ký không có trong trust cache, AMFI sẽ từ chối tải nó.

### Liệt kê Trust Cache

Các file trust cache nói trên có định dạng **IMG4** và **IM4P**; IM4P là phần payload của định dạng IMG4.

Bạn có thể dùng [**pyimg4**](https://github.com/m1stadev/PyIMG4) để trích xuất payload của các cơ sở dữ liệu:

```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```

(Một lựa chọn khác là dùng công cụ [**img4tool**](https://github.com/tihmstar/img4tool), công cụ này vẫn chạy trên M1 dù bản phát hành đã cũ và dành cho x86_64, nếu bạn cài đặt nó vào đúng vị trí.)

Giờ đây, bạn có thể dùng công cụ [**trustcache**](https://github.com/CRKatri/trustcache) để xem thông tin ở định dạng dễ đọc:

```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```

Trust cache có cấu trúc như sau, vì vậy **LC category là cột thứ 4**.

```c
struct trust_cache_entry2 {
	uint8_t cdhash[CS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;
	uint8_t constraintCategory;
	uint8_t reserved0;
} __attribute__((__packed__));
```

Sau đó, bạn có thể dùng một script như [**script này**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) để trích xuất dữ liệu.

Từ dữ liệu đó, bạn có thể kiểm tra các ứng dụng có **giá trị launch constraints là `0`**; đây là những ứng dụng không bị ràng buộc ([**xem tại đây**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) để biết ý nghĩa của từng giá trị).<sup>[[6]](#references)</sup>

## Attack Mitigations

Launch Constraints có thể ngăn chặn một số cuộc tấn công cũ bằng cách **đảm bảo tiến trình không được thực thi trong các điều kiện bất ngờ:** chẳng hạn như từ các vị trí không mong đợi hoặc được gọi bởi một tiến trình cha không mong đợi (nếu chỉ launchd mới được phép khởi chạy tiến trình đó).

Ngoài ra, Launch Constraints còn **ngăn chặn các cuộc tấn công downgrade.**

Tuy nhiên, chúng **không ngăn chặn các hành vi lạm dụng XPC** phổ biến, các cuộc tấn công chèn mã **Electron** hoặc **dylib** khi không có library validation (trừ khi đã biết các team ID được phép tải thư viện).<sup>[[3]](#references)</sup>

### XPC Daemon Protection

Trong bản phát hành Sonoma, một điểm đáng chú ý là cấu hình **trách nhiệm** của dịch vụ XPC daemon. Dịch vụ XPC tự chịu trách nhiệm, thay vì để client kết nối chịu trách nhiệm. Điều này được ghi lại trong báo cáo phản hồi FB13206884. Cách thiết lập này có thể có vẻ thiếu sót vì cho phép một số tương tác nhất định với dịch vụ XPC:

- **Khởi chạy dịch vụ XPC**: Nếu xem đây là một lỗi, cách thiết lập này không cho phép khởi chạy dịch vụ XPC bằng mã của kẻ tấn công.
- **Kết nối với dịch vụ đang hoạt động**: Nếu dịch vụ XPC đã chạy (có thể được kích hoạt bởi ứng dụng gốc), không có rào cản nào ngăn việc kết nối với nó.

Việc áp dụng các ràng buộc cho dịch vụ XPC có thể hữu ích vì **thu hẹp khoảng thời gian có thể bị tấn công**, nhưng không giải quyết mối lo ngại chính. Để đảm bảo an toàn cho dịch vụ XPC, về cơ bản cần **xác thực hiệu quả client kết nối**. Đây vẫn là cách duy nhất để tăng cường bảo mật cho dịch vụ. Cũng cần lưu ý rằng cấu hình trách nhiệm nói trên hiện đang hoạt động, điều này có thể không phù hợp với thiết kế dự kiến.<sup>[[3]](#references)</sup>

### Electron Protection

Ngay cả khi yêu cầu ứng dụng phải được **mở bằng LaunchService** (trong các ràng buộc của tiến trình cha), điều này vẫn có thể thực hiện bằng **`open`** (có thể đặt biến môi trường) hoặc dùng **Launch Services API** (có thể chỉ định biến môi trường).<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Ghi đè các ràng buộc tích hợp sẵn tại thời điểm spawn

Launch Constraints (tên chính thức là **lightweight code requirements**, *LWCR*) được thực thi bởi **chính sách AMFI MAC**. `posix_spawn` cho phép bên gọi chuyển một blob tùy ý đến chính sách MAC thông qua **`posix_spawnattr_setmacpolicyinfo_np()`**, và AMFI chấp nhận một từ điển LWCR do bên gọi cung cấp thông qua đường dẫn đó. Lỗi nằm ở chỗ **các ràng buộc do kẻ tấn công cung cấp thay thế các ràng buộc tích hợp sẵn của binary**, thay vì được kiểm tra bổ sung cùng với chúng:

- Tạo một từ điển launch constraints tối giản (thậm chí rỗng).
- Đặt **constraint category thành `127`**, một giá trị AMFI cho phép trong spawn attributes nhưng **không thực thi** — AMFI chỉ ghi log `Launch Constraint Violation (not enforcing)` thay vì chặn việc thực thi.
- Truyền từ điển này qua spawn attributes để tiến trình khởi chạy trong một ngữ cảnh mà các ràng buộc thực tế của chính nó/tiến trình cha lẽ ra đã cấm.

Sau khi sửa lỗi, **cả hai** loại ràng buộc — tích hợp sẵn và do bên gọi cung cấp — đều được xác thực, nên từ điển được cung cấp không còn có thể làm suy yếu các ràng buộc tích hợp sẵn.<sup>[[2]](#references)</sup>

> [!TIP]
> Đây là dạng vấn đề thường cần tìm khi kiểm tra việc thực thi ràng buộc: API cho phép đầu vào không đáng tin cậy *cung cấp* một chính sách thường đáng được chú ý, nhất là khi bộ máy chính sách xem giá trị được cung cấp là thứ thay thế chứ không phải một yêu cầu bổ sung.

## References

- [1] [Objective by the Sea #OBTS v6.0 Ngày 2 (Phát trực tiếp)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Vượt qua Launch Constraints trên macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Phân tích chuyên sâu về Launch và Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Tại sao ứng dụng hệ thống hoặc công cụ dòng lệnh không chạy? Launch constraints và trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Bảo vệ ứng dụng Mac bằng environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Mô tả về Launch Constraints được giới thiệu trong iOS 16 (gist của LinusHenze)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [Launch Constraints trên macOS Sonoma (14) (gist của theevilbit)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Vượt xa LaunchAgents quen thuộc - xem thêm tại đây](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
