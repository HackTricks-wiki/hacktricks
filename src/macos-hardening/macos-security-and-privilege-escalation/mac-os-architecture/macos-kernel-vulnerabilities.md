# Lỗ hổng kernel macOS

{{#include ../../../banners/hacktricks-training.md}}

Việc khai thác kernel macOS gần đây ít xoay quanh chuyện “nạp một kext unsigned đơn giản để có quyền ring-0” hơn, mà tập trung vào việc lạm dụng **trình phân tích Mach/MIG**, **IOKit user client**, **các race data-only bên trong XNU** và **những daemon có entitlement đặc biệt** vẫn có thể mở lại bề mặt tấn công của kernel. Để phân tích ngược các giao diện cụ thể, hãy xem thêm các trang về [**IOKit**](macos-iokit.md) và [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Các bề mặt tấn công vẫn đáng chú ý

- **Mach/MIG handler** trong các daemon hệ thống và dịch vụ giao tiếp với kernel: descriptor bị định dạng sai, dữ liệu out-of-line (OOL) và các luồng xử lý trạng thái qua nhiều message.
- **IOKit user client**: phân tích dữ liệu riêng theo selector, các phương thức bị giới hạn bởi entitlement và thư viện wrapper/daemon che khuất call graph thực sự.
- **Các primitive data-only của XNU**: race liên quan đến credential, con trỏ được bảo vệ bằng SMR, vùng nhớ chỉ đọc và các vị trí khác mà việc memory corruption làm thay đổi chính sách mà không cần chiếm quyền điều khiển RIP/PC trước.
- **Mã kernel của bên thứ ba / mã phụ trợ**: kext cũ ít phổ biến hơn, nhưng các hệ thống doanh nghiệp, hệ thống Apple Silicon có chế độ bảo mật giảm và các gói `.fs` / helper của nhà cung cấp vẫn tạo ra những đường tấn công giá trị cao nằm gần kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Trong [**báo cáo này**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), một số lỗi trong chuỗi OTA/cập nhật được kết hợp để xâm phạm kernel bằng cách lạm dụng pipeline cập nhật phần mềm và các khả năng liên quan đến rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Chuỗi bypass cơ chế bảo vệ kernel đang bị khai thác ngoài thực tế (CVE-2024-23225 & CVE-2024-23296)

Các [**bản phát hành bảo mật macOS tháng 3 năm 2024**](https://support.apple.com/en-us/120895) của Apple đã sửa hai lỗi đang **bị khai thác tích cực**:<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**: lỗi memory corruption cho phép kẻ tấn công có quyền đọc/ghi kernel tùy ý bypass các cơ chế bảo vệ bộ nhớ của kernel.
- **CVE-2024-23296 – RTKit**: một lỗi memory corruption khác có cùng mô tả tác động công khai.

Thông tin công khai về nguyên nhân gốc vẫn còn ít, nhưng cặp lỗi này nhắc chúng ta rằng các chuỗi khai thác Apple hiện đại thường cần **nhiều hơn “chỉ” quyền đọc/ghi kernel**: công việc hậu khai thác nhằm xử lý các cơ chế bảo vệ bộ nhớ, mã liên quan đến coprocessor hoặc các ranh giới tin cậy thứ cấp thường là nơi giúp ổn định chuỗi khai thác thực sự.

Đánh giá nhanh bản vá:

```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```

---

## 2025: SMR + race trên credential chỉ đọc (CVE-2025-24118)

[**Bài phân tích TRAVERTINE**](https://jprx.io/cve-2025-24118/) của Joseph Ravichandran là một nghiên cứu điển hình rất hay về XNU hiện đại vì đây **không phải** là lỗi buffer overflow kinh điển:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` là một **pointer được SMR bảo vệ**, lưu trong một đối tượng `proc_ro` **chỉ đọc**.
- Các tiến trình ghi phải cập nhật pointer đó **một cách nguyên tử**.
- `kauth_cred_proc_update()` dùng `zalloc_ro_mut(...)` để sửa đổi `p_ucred`; trên x86_64, đường xử lý này cuối cùng gọi `memcpy` / `rep movsb`, nên một tiến trình đọc đồng thời có thể thấy **pointer bị ghi dở**.
- Lỗi này dẫn đến **privilege escalation chỉ bằng cách sửa dữ liệu**: nếu pointer credential bị hỏng trỏ đến một credential object hợp lệ khác, thread hiện tại có thể nhận trạng thái có đặc quyền cao hơn mà không cần trước tiên chiếm quyền điều khiển luồng thực thi một cách rõ ràng.

Mẫu kích hoạt tối thiểu:

```c
// writer thread: force frequent credential swaps
while (1) {
    setgid(real_gid);
    setgid(saved_or_effective_gid);
}

// reader thread: repeatedly dereference current credentials
while (1) {
    (void)getgid();
}
```

Heuristic audit hữu ích: bất cứ khi nào một đường dẫn trong kernel kết hợp **SMR readers**, **thay đổi vùng chỉ đọc** và **metadata thông tin xác thực hoặc task**, hãy xác minh rằng các bản cập nhật sử dụng các biến thể `zalloc_ro_mut_*` atomic thay vì các helper dựa trên thao tác sao chép.

---

## 2024-2025: SIP bypass mở lại các đường dẫn nạp kernel (CVE-2024-44243)

Microsoft cho thấy có thể lợi dụng `storagekitd` để **bypass SIP**, khiến code kernel của bên thứ ba lại trở nên liên quan trên những máy vốn được xem là đã ở thời kỳ "post-kext". Ý tưởng chính là:<sup>[[2]](#references)</sup>

1. Đặt hoặc ghi đè một bundle `.fs` độc hại trong `/Library/Filesystems`.
2. Kích hoạt `storagekitd` thông qua Disk Utility hoặc `diskutil`.
3. Để daemon có entitlement đặc biệt khởi chạy các executable trong bundle **mà không hạ quyền đúng cách / xác thực đường dẫn**.
4. Dùng SIP bypass thu được để thay đổi trạng thái file system được bảo vệ và, trong minh họa của Microsoft, ghi đè danh sách loại trừ kernel extension.

Bài học quan trọng đối với các nhà nghiên cứu kernel là **attack surface của kernel có thể được đưa trở lại thông qua các daemon quản lý từ userland**, ngay cả khi việc nạp kext của bên thứ ba bị hạn chế nghiêm ngặt.

Triage hữu ích:

```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```

---

## Quy trình Fuzzing và nghiên cứu

Nếu bạn đang tích cực tìm kiếm nhóm lỗi này, các nghiên cứu công khai gần đây đều chỉ về cùng một hướng:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) vẫn là một trong những tài liệu tham khảo tốt nhất cho nghiên cứu kernel trong kỷ nguyên Apple Silicon. Công cụ này dùng **static binary rewriting** để khôi phục coverage, vô hiệu hóa các đường dẫn **entitlement-gated** trong quá trình kiểm thử và suy luận cấu trúc interface từ các wrapper userspace.<sup>[[4]](#references)</sup>
- Bài viết của Project Zero [**Fuzzing kernel extension macOS trong userspace một cách đơn giản với IDA và TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) trình bày một quy trình rất thực tiễn để **rebase kext / fileset vào userspace**, nhờ đó có thể fuzz code xử lý parser với tốc độ cao hơn nhiều trước khi tái hiện lỗi trên thiết bị.<sup>[[5]](#references)</sup>
- Với các mục tiêu thiên về Mach, hãy xây dựng harness dựa trên **message layout thực tế và state machine gồm nhiều lần gọi**, thay vì chỉ dùng các selector blob đơn lẻ. Nghiên cứu CoreAudio/Mach gần đây từ Project Zero và các bài thuyết trình tại hội nghị như **Fuzzing at Mach Speed** cho thấy vì sao các chuỗi message có trạng thái vẫn tiếp tục mang lại hiệu quả.

Các lệnh nhanh chạy cục bộ mà bạn sẽ dùng thường xuyên:

```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```

## Cheatsheet Enumeration nhanh

```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```

## References

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Phân tích CVE-2024-44243, lỗ hổng bypass System Integrity Protection trên macOS thông qua kernel extension](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Cơn ác mộng về bản cập nhật OTA của Apple: Bypass xác minh chữ ký và chiếm quyền kiểm soát kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing kernel extension của macOS trên Apple Silicon bằng cách khai thác các biện pháp giảm thiểu (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Fuzzing kernel extension của macOS đơn giản trong userspace bằng IDA và TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [Giới thiệu về nội dung bảo mật của macOS Sonoma 14.4 - Apple Support](https://support.apple.com/en-us/120895)
{{#include ../../../banners/hacktricks-training.md}}
