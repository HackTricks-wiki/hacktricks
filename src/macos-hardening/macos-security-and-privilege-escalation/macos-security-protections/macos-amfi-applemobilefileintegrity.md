# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext và amfid

AMFI tập trung vào việc thực thi tính toàn vẹn của code chạy trên hệ thống, cung cấp logic phía sau quá trình xác minh chữ ký code của XNU. Nó cũng có thể kiểm tra entitlements và xử lý các tác vụ nhạy cảm khác như cho phép debugging hoặc lấy task ports.

Ngoài ra, với một số thao tác, kext ưu tiên liên hệ với daemon user space `/usr/libexec/amfid`. Mối quan hệ tin cậy này đã bị lạm dụng trong một số jailbreak.

Trên các phiên bản macOS gần đây, AMFI không còn được cung cấp thuận tiện dưới dạng kext độc lập trên đĩa, vì vậy việc reverse thường đòi hỏi làm việc với **kernelcache** hoặc **KDK**, thay vì duyệt `/System/Library/Extensions`.

AMFI sử dụng các chính sách **MACF** và đăng ký các hook ngay khi khởi động. Ngoài ra, việc ngăn nó tải hoặc gỡ nó có thể gây kernel panic. Tuy nhiên, có một số boot arguments cho phép vô hiệu hóa AMFI:

- `amfi_unrestricted_task_for_pid`: Cho phép task_for_pid mà không cần các entitlements bắt buộc
- `amfi_allow_any_signature`: Cho phép mọi chữ ký code
- `cs_enforcement_disable`: Argument toàn hệ thống dùng để tắt việc thực thi code signing
- `amfi_prevent_old_entitled_platform_binaries`: Vô hiệu hóa platform binaries có entitlements
- `amfi_get_out_of_my_way`: Tắt hoàn toàn amfi

Đây là một số chính sách MACF mà AMFI đăng ký:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Thực hiện cập nhật label và trả về 1
- **`cred_label_associate`**: Cập nhật slot mac label của AMFI bằng label
- **`cred_label_destroy`**: Xóa slot mac label của AMFI
- **`cred_label_init`**: Đặt 0 vào slot mac label của AMFI
- **`cred_label_update_execve`:** Kiểm tra entitlements của process để xác định liệu process có được phép sửa đổi các label hay không.
- **`file_check_mmap`:** Kiểm tra xem mmap có đang cấp phát memory và đặt memory đó thành executable hay không. Nếu có, hàm kiểm tra xem có cần library validation không; nếu cần, hàm sẽ gọi function library validation.
- **`file_check_library_validation`**: Gọi function library validation, kiểm tra, cùng những thứ khác, liệu platform binary có đang tải một platform binary khác hay process và file mới được tải có cùng TeamID hay không. Một số entitlements cũng cho phép tải bất kỳ library nào.
- **`policy_initbsd`**: Thiết lập các NVRAM Keys đáng tin cậy
- **`policy_syscall`**: Kiểm tra các chính sách DYLD, chẳng hạn binary có unrestricted segments hay không, có nên cho phép env vars hay không... Hàm này cũng được gọi khi một process khởi chạy thông qua `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Kiểm tra xem khi một process thực thi binary mới, các process khác có quyền SEND trên task port của process đó có được giữ quyền hay không. Platform binaries được phép; entitlement `get-task-allow` cho phép việc này; entitlement `task_for_pid-allow` cũng được cho phép; các binary có cùng TeamID cũng được phép.
- **`proc_check_expose_task`**: Thực thi entitlements
- **`amfi_exc_action_check_exception_send`**: Gửi một exception message đến debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Vòng đời của label trong quá trình xử lý exception (debugging)
- **`proc_check_get_task`**: Kiểm tra các entitlements như `get-task-allow`, cho phép process khác lấy task port, và `task_for_pid-allow`, cho phép process lấy task ports của các process khác. Nếu không có entitlement nào trong số này, hàm sẽ gọi `amfid permitunrestricteddebugging` để kiểm tra xem có được phép hay không.
- **`proc_check_mprotect`**: Từ chối nếu `mprotect` được gọi với flag `VM_PROT_TRUSTED`, cho biết vùng memory phải được xử lý như thể có chữ ký code hợp lệ.
- **`vnode_check_exec`**: Được gọi khi các executable files được tải vào memory và đặt `cs_hard | cs_kill`, khiến process bị kill nếu bất kỳ page nào trở nên không hợp lệ<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: macOS: Kiểm tra `com.apple.root.installed` và `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Như get + entitlement `com.apple.private.allow-bless` và `internal-installer-equivalent`
- **`vnode_check_signature`**: Code gọi XNU để kiểm tra chữ ký code bằng entitlements, trust cache và `amfid`<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: Chặn các lệnh gọi `ptrace()` (`PT_ATTACH` và `PT_TRACE_ME`). Hàm kiểm tra các entitlements `get-task-allow`, `run-invalid-allow` và `run-unsigned-code`; nếu không có entitlement nào, hàm sẽ kiểm tra xem debugging có được phép hay không.
- **`proc_check_map_anon`**: Nếu mmap được gọi với flag **`MAP_JIT`**, AMFI sẽ kiểm tra entitlement `dynamic-codesigning`.

`AMFI.kext` cũng cung cấp một API cho các kernel extensions khác. Có thể tìm các dependencies của nó bằng lệnh sau:

```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
   8   com.apple.kec.corecrypto
  19   com.apple.driver.AppleMobileFileIntegrity
  22   com.apple.security.sandbox
  24   com.apple.AppleSystemPolicy
  67   com.apple.iokit.IOUSBHostFamily
  70   com.apple.driver.AppleUSBTDM
  71   com.apple.driver.AppleSEPKeyStore
  74   com.apple.iokit.EndpointSecurity
  81   com.apple.iokit.IOUserEthernet
 101   com.apple.iokit.IO80211Family
 102   com.apple.driver.AppleBCMWLANCore
 118   com.apple.driver.AppleEmbeddedUSBHost
 134   com.apple.iokit.IOGPUFamily
 135   com.apple.AGXG13X
 137   com.apple.iokit.IOMobileGraphicsFamily
 138   com.apple.iokit.IOMobileGraphicsFamily-DCP
 162   com.apple.iokit.IONVMeFamily
```

## amfid

Đây là daemon chạy ở user mode mà `AMFI.kext` sử dụng để kiểm tra code signature ở user mode.\
Để `AMFI.kext` giao tiếp với daemon, nó dùng mach messages qua port `HOST_AMFID_PORT`, tức special port `18`.

Lưu ý rằng trong macOS, các process root không còn có thể chiếm special ports vì chúng được bảo vệ bởi `SIP` và chỉ launchd mới có thể lấy được. Trong iOS, hệ thống kiểm tra rằng process gửi phản hồi có CDHash được hardcode của `amfid`.

Có thể quan sát thời điểm `amfid` được yêu cầu kiểm tra một binary và phản hồi của nó bằng cách debug process này rồi đặt breakpoint trong `mach_msg`.

Sau khi nhận được message qua special port, **MIG** sẽ được dùng để gửi từng function đến function mà nó gọi. Các function chính đã được reverse và giải thích trong cuốn sách.

### Chính sách DYLD và library validation

Các phiên bản `dyld` gần đây gọi `amfi_check_dyld_policy_self()` rất sớm từ `configureProcessRestrictions()` để hỏi AMFI xem process có được phép sử dụng các biến đường dẫn `DYLD_*`, interposing, fallback paths, embedded variables hoặc bỏ qua lỗi chèn thư viện hay không. Vì vậy, khi phân loại một injection surface, chỉ kiểm tra Mach-O load commands là chưa đủ: bạn cũng cần kiểm tra entitlements và runtime flags mà AMFI sẽ chuyển thành chính sách `dyld`.

Quy trình phân loại thực tế là:

```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
  egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```

Trên các phiên bản macOS hiện đại, nhiều binary của Apple không còn trực tiếp mang entitlement `com.apple.security.cs.disable-library-validation`, mà thay vào đó có `com.apple.private.security.clear-library-validation`. Trong trường hợp đó, library validation không bị tắt tại thời điểm `execve`: process phải tự gọi `csops(..., CS_OPS_CLEAR_LV, ...)`, và XNU chỉ cho phép process gọi thao tác này trên chính nó khi có entitlement. Từ góc độ tấn công, điều này quan trọng vì target có thể chỉ cho phép injection **sau khi** đi đến code path chủ động xóa LV (ví dụ: ngay trước khi tải các plugin tùy chọn).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Provisioning profile có thể được dùng để ký code. Có các profile **Developer** dùng để ký code và kiểm thử, và các profile **Enterprise** có thể dùng trên mọi thiết bị.

Sau khi một App được gửi lên Apple Store và được phê duyệt, Apple sẽ ký App đó và provisioning profile không còn cần thiết nữa.

Profile thường có phần mở rộng `.mobileprovision` hoặc `.provisionprofile` và có thể được trích xuất bằng:

```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```

Mặc dù đôi khi được gọi là chứng chỉ, các provisioning profile này chứa nhiều thông tin hơn một chứng chỉ:

- **AppIDName:** Định danh ứng dụng
- **AppleInternalProfile**: Đánh dấu đây là profile nội bộ của Apple
- **ApplicationIdentifierPrefix**: Tiền tố được thêm vào AppIDName (giống với TeamIdentifier)
- **CreationDate**: Ngày theo định dạng `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Mảng chứa (thường là một) chứng chỉ được mã hóa dưới dạng dữ liệu Base64
- **Entitlements**: Các entitlements được phép dùng với profile này
- **ExpirationDate**: Ngày hết hạn theo định dạng `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Tên ứng dụng, giống với AppIDName
- **ProvisionedDevices**: Mảng UDID (dành cho chứng chỉ nhà phát triển) mà profile này có hiệu lực
- **ProvisionsAllDevices**: Giá trị boolean (true đối với chứng chỉ doanh nghiệp)
- **TeamIdentifier**: Mảng gồm (thường là một) chuỗi chữ và số dùng để nhận diện nhà phát triển cho mục đích tương tác giữa các ứng dụng
- **TeamName**: Tên dễ đọc dùng để nhận diện nhà phát triển
- **TimeToLive**: Thời hạn hiệu lực của chứng chỉ (tính bằng ngày)
- **UUID**: Mã định danh duy nhất toàn cục cho profile này
- **Version**: Hiện được đặt thành 1

Lưu ý rằng mục entitlements sẽ chứa một tập hợp entitlements bị giới hạn, và provisioning profile chỉ có thể cấp những entitlements cụ thể đó nhằm ngăn việc cấp các private entitlements của Apple.

Các profile thường nằm trong `/var/MobileDeviceProvisioningProfiles` và có thể kiểm tra bằng lệnh **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Đây là thư viện bên ngoài mà `amfid` gọi để hỏi xem có nên cho phép một thứ gì đó hay không. Trong lịch sử, thư viện này từng bị lợi dụng trong quá trình jailbreak bằng cách chạy phiên bản đã cài backdoor, phiên bản này sẽ cho phép mọi thứ.

Trong macOS, thư viện này nằm trong `MobileDevice.framework`.

## AMFI Trust Caches

Trust cache không chỉ là khái niệm của iOS. Trên các phiên bản macOS hiện đại, đặc biệt là trên **Apple silicon**, trust cache tĩnh và trust cache có thể tải là một phần của chuỗi Secure Boot. Khi **CodeDirectory hash** của một Mach-O có trong đó, AMFI có thể cấp cho nó **platform privilege** mà không cần thực hiện thêm các bước xác thực khi khởi chạy. Điều này cũng cho phép Apple khóa các binary nền tảng theo một phiên bản OS cụ thể và ngăn các binary cũ do Apple ký bị phát lại trên hệ thống mới hơn.<sup>[[6]](#references)</sup>

Trên các bản macOS gần đây, metadata của trust cache cũng gắn với **launch constraints**, vì vậy các ứng dụng hệ thống và binary được sao chép, hoặc khởi chạy từ sai parent/location, có thể bị AMFI từ chối ngay cả khi chúng vẫn được Apple ký. Quy trình trích xuất và phân tích chi tiết được trình bày trong:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Trong nghiên cứu iOS và jailbreak, bạn vẫn sẽ thấy mô hình truyền thống dùng **loadable trust caches** để đưa các binary được ký ad-hoc vào danh sách cho phép.

## References

- [1] [XNU — `security/mac_policy.h` (các thao tác policy MACF mà AMFI đăng ký, bao gồm `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (các cờ ký mã `CS_*` mà AMFI thiết lập)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (phân tích cú pháp và xác thực code-signature blob)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (các thao tác `CS_OPS_*` và `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (trình xử lý `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Hướng dẫn bảo mật nền tảng Apple — Trust cache](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)
{{#include ../../../banners/hacktricks-training.md}}
