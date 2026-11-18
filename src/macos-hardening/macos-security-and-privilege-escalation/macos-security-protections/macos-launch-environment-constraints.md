# Ràng buộc Launch/Environment của macOS & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

Launch constraints trong macOS được giới thiệu nhằm tăng cường bảo mật bằng cách **điều chỉnh cách thức, đối tượng và nguồn khởi chạy một tiến trình**. Được giới thiệu từ macOS Ventura, chúng cung cấp một framework phân loại **mỗi system binary thành các nhóm constraint riêng biệt**, được định nghĩa trong **trust cache** — danh sách chứa system binary cùng các hash tương ứng. Những constraint này áp dụng cho mọi executable binary trong hệ thống, bao gồm một tập hợp **quy tắc** xác định các yêu cầu để **khởi chạy một binary cụ thể**. Các quy tắc bao gồm self constraint mà binary phải đáp ứng, parent constraint mà tiến trình cha phải đáp ứng và responsible constraint mà các thực thể liên quan khác phải tuân thủ.<sup>[[1]](#references)[[4]](#references)</sup>

Cơ chế này được mở rộng cho các ứng dụng bên thứ ba từ macOS Sonoma thông qua **Environment Constraints**, cho phép nhà phát triển bảo vệ ứng dụng bằng cách chỉ định **một tập hợp key và value cho environment constraint.**<sup>[[5]](#references)</sup>

Bạn định nghĩa **launch environment và library constraint** trong các constraint dictionary mà bạn lưu trong **tệp property list của `launchd`** hoặc trong các tệp **property list riêng biệt** được dùng trong code signing.<sup>[[5]](#references)</sup>

Có 4 loại constraint:

- **Self Constraints**: Constraint áp dụng cho binary **đang chạy**.
- **Parent Process**: Constraint áp dụng cho **tiến trình cha của tiến trình** (ví dụ **`launchd`** chạy một dịch vụ XP)
- **Responsible Constraints**: Constraint áp dụng cho **tiến trình gọi dịch vụ** trong giao tiếp XPC
- **Library load constraints**: Dùng library load constraint để mô tả có chọn lọc đoạn code có thể được tải

Vì vậy, khi một tiến trình cố gắng khởi chạy một tiến trình khác — bằng cách gọi `execve(_:_:_:)` hoặc `posix_spawn(_:_:_:_:_:_:)` — hệ điều hành kiểm tra xem tệp **executable** có **đáp ứng** **self constraint** của chính nó hay không. Hệ điều hành cũng kiểm tra xem executable của **tiến trình cha** có **đáp ứng parent constraint** của executable đó hay không, và executable của **tiến trình chịu trách nhiệm** có **đáp ứng responsible process constraint** của executable đó hay không. Nếu bất kỳ launch constraint nào không được đáp ứng, hệ điều hành sẽ không chạy chương trình.

Nếu bất kỳ phần nào của **library constraint không đúng** khi tải một library, tiến trình của bạn **sẽ không tải** library đó.

## Các nhóm LC

Một LC được cấu thành từ **các fact** và **các phép toán logic** (and, or...) kết hợp những fact này.

[Các **fact mà một LC có thể sử dụng được ghi lại tại đây**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Ví dụ:

- is-init-proc: Giá trị Boolean cho biết executable có phải là tiến trình khởi tạo của hệ điều hành (`launchd`) hay không.
- is-sip-protected: Giá trị Boolean cho biết executable có phải là tệp được System Integrity Protection (SIP) bảo vệ hay không.
- `on-authorized-authapfs-volume:` Giá trị Boolean cho biết hệ điều hành đã tải executable từ một APFS volume được ủy quyền và xác thực hay không.
- `on-authorized-authapfs-volume`: Giá trị Boolean cho biết hệ điều hành đã tải executable từ một APFS volume được ủy quyền và xác thực hay không.
  - Volume Cryptexes
- `on-system-volume:`Giá trị Boolean cho biết hệ điều hành đã tải executable từ system volume hiện đang được khởi động hay không.
  - Bên trong /System...
- ...

Khi một binary của Apple được ký, **nó sẽ được gán vào một nhóm LC** trong **trust cache**.

- Các **nhóm LC của iOS 16** đã được [**reverse và ghi lại tại đây**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Các **nhóm LC hiện tại (macOS 14** - Somona) đã được reverse và [**mô tả có thể tìm thấy tại đây**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Ví dụ, Category 1 là:<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: Phải nằm trên volume System hoặc Cryptexes.
- `launch-type == 1`: Phải là system service (plist trong LaunchDaemons).
- `validation-category == 1`: Tệp thực thi của hệ điều hành.
- `is-init-proc`: Launchd

### Đảo ngược các danh mục LC

Bạn có thể tìm thêm thông tin [**tại đây**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), nhưng về cơ bản, chúng được định nghĩa trong **AMFI (AppleMobileFileIntegrity)**, vì vậy bạn cần tải Kernel Development Kit để lấy **KEXT**. Các symbol bắt đầu bằng **`kConstraintCategory`** là những symbol **đáng chú ý**. Trích xuất chúng sẽ cho bạn một luồng được mã hóa theo DER (ASN.1), bạn cần giải mã bằng [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) hoặc thư viện python-asn1 cùng script `dump.py` của nó, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), để thu được một chuỗi dễ hiểu hơn.<sup>[[3]](#references)[[8]](#references)</sup>

## Ràng buộc môi trường

Đây là các Launch Constraints được cấu hình trong **ứng dụng bên thứ ba**. Nhà phát triển có thể chọn các **facts** và **toán tử logic** để sử dụng trong ứng dụng nhằm hạn chế quyền truy cập vào ứng dụng đó.

Có thể liệt kê Environment Constraints của một ứng dụng bằng:

```bash
codesign -d -vvvv app.app
```

## Trust Caches

Trong **macOS** có một số trust cache:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Còn trong iOS, trust cache có vẻ nằm ở **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Trên macOS chạy trên thiết bị Apple Silicon, nếu một binary được Apple ký không có trong trust cache, AMFI sẽ từ chối tải nó.

### Liệt kê Trust Cache

Các tệp trust cache ở trên có định dạng **IMG4** và **IM4P**; IM4P là phần payload của định dạng IMG4.

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

(Một lựa chọn khác là dùng công cụ [**img4tool**](https://github.com/tihmstar/img4tool), công cụ này vẫn chạy được trên M1 dù bản phát hành đã cũ và dành cho x86_64, nếu bạn cài đặt nó vào đúng vị trí.)

Giờ bạn có thể dùng công cụ [**trustcache**](https://github.com/CRKatri/trustcache) để xem thông tin ở định dạng dễ đọc:

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

Trust cache tuân theo cấu trúc sau, vì vậy **danh mục LC là cột thứ 4**

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

Từ dữ liệu đó, bạn có thể kiểm tra các ứng dụng có **giá trị launch constraints là `0`** — đây là những ứng dụng không bị ràng buộc (xem [**tại đây**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) để biết ý nghĩa của từng giá trị).<sup>[[6]](#references)</sup>

## Biện pháp giảm thiểu tấn công

Launch Constraints có thể đã giảm thiểu một số cuộc tấn công cũ bằng cách **đảm bảo tiến trình không được thực thi trong những điều kiện bất ngờ:** chẳng hạn như từ các vị trí không mong đợi hoặc được khởi chạy bởi một tiến trình cha không mong đợi (nếu chỉ launchd mới được phép khởi chạy tiến trình đó).

Ngoài ra, Launch Constraints cũng **giảm thiểu các cuộc tấn công downgrade.**

Tuy nhiên, chúng **không giảm thiểu các hành vi lạm dụng XPC phổ biến**, việc chèn mã **Electron** hoặc **chèn dylib** khi không có library validation (trừ khi đã biết các team ID được phép tải thư viện).<sup>[[3]](#references)</sup>

### Bảo vệ XPC Daemon

Trong bản phát hành Sonoma, một điểm đáng chú ý là cấu hình **trách nhiệm** của dịch vụ XPC daemon. Dịch vụ XPC tự chịu trách nhiệm, thay vì để client kết nối chịu trách nhiệm. Điều này được ghi lại trong báo cáo phản hồi FB13206884. Cách thiết lập này có vẻ thiếu sót vì nó cho phép một số tương tác nhất định với dịch vụ XPC:

- **Khởi chạy dịch vụ XPC**: Nếu xem đây là lỗi, cách thiết lập này không cho phép khởi chạy dịch vụ XPC bằng mã của attacker.
- **Kết nối với dịch vụ đang hoạt động**: Nếu dịch vụ XPC đã chạy (có thể được kích hoạt bởi ứng dụng ban đầu), không có rào cản nào ngăn việc kết nối với dịch vụ đó.

Việc áp dụng các ràng buộc cho dịch vụ XPC có thể hữu ích vì **thu hẹp khoảng thời gian có thể xảy ra tấn công**, nhưng không giải quyết mối lo ngại chính. Để đảm bảo an toàn cho dịch vụ XPC, về cơ bản cần **xác thực hiệu quả client kết nối**. Đây vẫn là cách duy nhất để tăng cường bảo mật cho dịch vụ. Cũng cần lưu ý rằng cấu hình trách nhiệm được đề cập hiện đang hoạt động, điều này có thể không phù hợp với thiết kế dự kiến.<sup>[[3]](#references)</sup>

### Bảo vệ Electron

Ngay cả khi yêu cầu ứng dụng phải được **LaunchService mở** (trong các ràng buộc của tiến trình cha), vẫn có thể đáp ứng yêu cầu này bằng **`open`** (có thể thiết lập biến môi trường) hoặc bằng **Launch Services API** (có thể chỉ định biến môi trường).<sup>[[3]](#references)</sup>

Để tìm hiểu cơ chế MACF tổng quát đứng sau các thuộc tính spawn dành riêng cho policy, xem [các thuộc tính spawn dành riêng cho policy của MACF](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).

### CVE-2025-43253 - Ghi đè các ràng buộc tích hợp sẵn tại thời điểm spawn

Launch constraints (tên chính thức là **lightweight code requirements**, *LWCR*) được thực thi bởi **AMFI MAC policy**. `posix_spawn` cho phép caller chuyển một blob tùy ý đến MAC policy thông qua **`posix_spawnattr_setmacpolicyinfo_np()`**, và AMFI chấp nhận một dictionary LWCR do caller cung cấp thông qua đường này. Lỗi nằm ở chỗ **các ràng buộc do attacker cung cấp thay thế các ràng buộc tích hợp sẵn của binary**, thay vì được kiểm tra bổ sung cùng với chúng:

- Tạo một dictionary launch constraints tối giản (thậm chí để trống).
- Đặt **constraint category thành `127`**, một giá trị được AMFI cho phép trong spawn attributes nhưng **không thực thi** — nó chỉ ghi log `Launch Constraint Violation (not enforcing)` thay vì chặn việc thực thi.
- Truyền dictionary này qua spawn attributes, để tiến trình khởi chạy trong một ngữ cảnh mà các ràng buộc thực tế của chính nó/tiến trình cha vốn sẽ cấm.

Sau khi được khắc phục, **cả hai** loại ràng buộc — tích hợp sẵn và do người dùng cung cấp — đều được xác thực, vì vậy dictionary được cung cấp không còn có thể làm suy yếu các ràng buộc tích hợp sẵn.<sup>[[2]](#references)</sup>

> [!TIP]
> Đây là dạng vấn đề tổng quát cần tìm khi kiểm tra việc thực thi constraint: một API cho phép đầu vào không đáng tin cậy *cung cấp* policy thường đáng chú ý nếu policy engine xử lý giá trị được cung cấp như một giá trị thay thế thay vì một yêu cầu bổ sung.



## References

- [1] [Objective by the Sea #OBTS v6.0 Ngày 2 (Phát trực tiếp)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Vượt qua Launch Constraints trên macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Tìm hiểu chuyên sâu về Launch and Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Tại sao ứng dụng hệ thống hoặc công cụ dòng lệnh không chạy? Launch constraints và trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Bảo vệ ứng dụng Mac bằng environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Mô tả về Launch Constraints được giới thiệu trong iOS 16 (gist của LinusHenze)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [Launch Constraints của macOS Sonoma (14) (gist của theevilbit)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Vượt xa LaunchAgents quen thuộc - xem thêm tại đây](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
