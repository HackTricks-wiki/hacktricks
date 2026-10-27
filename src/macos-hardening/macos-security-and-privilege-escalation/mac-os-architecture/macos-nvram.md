# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

**NVRAM** (Non-Volatile Random-Access Memory) lưu trữ trạng thái firmware và trạng thái khởi động sớm bên ngoài hệ thống tệp macOS thông thường. Tác động bảo mật của nó phụ thuộc vào cả biến được lưu trữ lẫn kiến trúc khởi động:

| Biến | Mục đích / mức độ liên quan đến bảo mật |
|---|---|
| `boot-args` | Các đối số được truyền cho kernel. Các đối số dùng để gỡ lỗi hoặc làm giảm bảo mật sẽ bị lọc, trừ khi boot policy cho phép. |
| `csr-active-config` | Bitmask SIP trên máy Mac dùng Intel. Trên Apple silicon, policy tương đương được lưu trong `LocalPolicy` của từng volume, chứ không được tin cậy trực tiếp từ biến này. |
| `efi-boot-device` / `efi-boot-device-data` | Mục tiêu khởi động EFI trên máy Mac dùng Intel. |
| `boot-volume` | Trạng thái chọn volume khởi động trên Apple silicon. |
| `SystemAudioVolume`, `prev-lang:kbd` | Ví dụ về các cài đặt thông thường được lưu liên tục. |

Điểm khác biệt quan trọng là giữa **dữ liệu được lưu trong NVRAM** và **security policy được chuỗi khởi động chấp nhận**. Trên Apple silicon, Secure Enclave ký `LocalPolicy` cho từng nhóm volume khởi động; nonce được lưu trong Secure Storage Component giúp chống phát lại. Vì vậy, việc thay đổi một thuộc tính NVRAM có tên tương tự không tự nó ghi đè boot policy được chấp nhận.<sup>[[1]](#references)[[4]](#references)</sup>

## Truy cập NVRAM từ User Space

### Đọc và thu thập dữ liệu cơ sở

```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```

Đừng phân loại mọi khóa lạ là độc hại. Phần cứng, recoveryOS, bản cập nhật, Find My và lỗi khởi động đều tạo ra các biến phụ thuộc vào kiểu máy và phiên bản. So sánh bản capture với baseline trước đó từ **cùng một máy Mac**, và xem các binary blob bất ngờ, lựa chọn khởi động đã thay đổi hoặc đối số làm giảm bảo mật là manh mối, chứ không phải bằng chứng máy đã bị xâm nhập.

### Ghi NVRAM

Root có thể tạo hoặc thay đổi nhiều biến thông thường, nhưng các biến được bảo vệ còn phụ thuộc vào namespace của biến, SIP, quy tắc kernel áp dụng cho từng biến và các Apple entitlement bị giới hạn. Vì vậy, việc `sudo` thành công với một khóa tùy chỉnh vô hại **không** chứng minh rằng tiến trình có thể sửa đổi `boot-args`, SIP hoặc các biến thuộc system region.

```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```

> [!CAUTION]
> Tránh dùng `nvram -c` trong quá trình kiểm thử: lệnh này yêu cầu xóa tất cả biến có thể xóa và có thể làm thay đổi hành vi khởi động/khôi phục. Một số biến chỉ dành cho kernel, được bảo vệ bằng entitlement, bị ẩn khi đọc hoặc chỉ có thể xóa trong quá trình đặt lại NVRAM.

## Entitlements của NVRAM và `CS_NVRAM_UNRESTRICTED`

Khi thực thi, XNU ánh xạ `com.apple.rootless.restricted-nvram-variables.heritable` thành cờ tiến trình **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). Điều này không tương đương với việc kiểm tra UID hiệu lực 0 thông thường. Ngoài ra còn có các entitlement riêng tư hẹp hơn cho những biến hoặc thao tác cụ thể.

Kiểm tra các entitlement thay vì dựa vào dòng cờ chung do `codesign` in ra:

```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
  grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```

Khi kiểm tra một helper có đặc quyền, hãy truy vết **danh tính client thực tế và đường dẫn yêu cầu**. Một lỗi confused-deputy trong dịch vụ có entitlement có thể hữu ích hơn việc gọi trực tiếp `nvram`, nhưng biến/thao tác có thể truy cập vẫn bị XNU hạn chế.

## Trạng thái SIP trên Intel so với `LocalPolicy` trên Apple Silicon

### Intel: `csr-active-config`

Trên Intel, `csr-active-config` mã hóa các ngoại lệ `CSR_ALLOW_*`. Các vị trí bit thường liên quan là:

```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```

Đọc cài đặt đang có hiệu lực bằng `csrutil status`; đầu ra `nvram` thô có thể dùng các byte little-endian được mã hóa phần trăm. Xem [macOS SIP](../macos-security-protections/macos-sip.md) để biết các tác động đến cơ chế bảo vệ và bypass.

```bash
nvram csr-active-config 2>/dev/null
csrutil status
```

### Apple Silicon: kiểm tra chính sách khởi động được chấp nhận

Trên Apple silicon, `sip0` trong `LocalPolicy` được Secure Enclave ký chứa các bit chính sách SIP trước đây được lưu trong NVRAM. Các trường chính sách liên quan khác là `sip1` (cho phép xác minh root hash của SSV thất bại), `sip2` (không khóa bộ nhớ kernel bằng CTRR) và `sip3` (vô hiệu hóa allowlist `boot-args` của iBoot). Các trường này chỉ có thể được thay đổi từ One True recoveryOS (1TR) đã ghép đôi; bật `sip3` cũng yêu cầu hạ cấp xuống Permissive Security.<sup>[[4]](#references)</sup>

Khi liệt kê, chỉ sử dụng các thao tác hiển thị:

```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```

> [!WARNING]
> Không sử dụng các tùy chọn thay đổi chính sách của `bputil` trong quá trình kiểm tra. Một vụ xâm nhập macOS thông thường không thể âm thầm bật các trường trên: con đường hạ cấp cố ý yêu cầu thao tác vật lý trong 1TR đã ghép đôi và xác thực chủ sở hữu.<sup>[[4]](#references)</sup>

## Implications về bảo mật

### `boot-args` như một công cụ khuếch đại sau khi bị xâm nhập

Các đối số như tùy chọn gỡ lỗi kernel, `kcsuffix=development` hoặc `amfi_get_out_of_my_way=1` có thể làm suy yếu các giai đoạn khởi động sau, nhưng chỉ khi nền tảng chấp nhận chúng. Trên Apple silicon ở chế độ Full hoặc Reduced Security, iBoot lọc các đối số làm giảm bảo mật; các đối số không bị hạn chế đòi hỏi phải hạ cấp chính sách `sip3` như mô tả ở trên. Trên Intel, giới hạn NVRAM của SIP cũng ngăn việc xem quyền truy cập root shell là khả năng tự động kiểm soát `boot-args`.

```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
  grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```

Xem [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) và [kernel debugging](macos-kernel-extensions.md) thay vì cho rằng một tham số lịch sử hoạt động giống hệt nhau trên mọi bản phát hành macOS.

### Thực thi `rc.trampoline` dựa trên NVRAM

Nghiên cứu gần đây đã ghi nhận một thành phần cụ thể sử dụng dữ liệu NVRAM: binary nền tảng Apple `/System/Library/CoreServices/rc.trampoline`. Khi launchd thấy boot argument `rc.trampoline=1`, tác vụ khởi động này đọc thuộc tính `apple-trusted-trampoline` từ `IODeviceTree:/options`, ghi thuộc tính đó vào một tệp thực thi tạm thời, khởi chạy tiến trình ở trạng thái tạm dừng, kiểm tra trạng thái code-signing, hủy liên kết tệp rồi tiếp tục tiến trình. Tác vụ khởi động chặn launchd cho đến khi tiến trình con thoát.<sup>[[5]](#references)</sup>

Đây là một **primitive duy trì quyền truy cập sau khi hạ cấp bảo mật, không phải SIP bypass**. Đường thực thi được chứng minh yêu cầu SIP bị tắt để tác vụ khởi động chạy và có thể thiết lập `boot-args`. Nghiên cứu cũng ghi nhận giới hạn kích thước giá trị khoảng 390 KB. Giá trị của kỹ thuật này là các byte thực thi có thể được lưu ngoài filesystem thông thường và được tạo thành tệp khi khởi động, sau khi kẻ tấn công đã đạt được mức hạ cấp bảo mật cần thiết.<sup>[[5]](#references)</sup>

Tìm kiếm cả hai artifact bắt buộc và sự kiện launchd:

```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
  --predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```

Các biến NVRAM tùy chỉnh tùy ý chỉ là **nơi lưu trữ**: chúng không tự thực thi gì trừ khi firmware, một thành phần khởi động của Apple hoặc một cơ chế duy trì hiện diện riêng biệt sử dụng chúng. Sự phân biệt này giúp tránh phóng đại một dấu mốc như `nvram attacker-config=...` thành khả năng thực thi mã firmware.

## Script liệt kê

<details>
<summary>Kiểm tra NVRAM và chính sách khởi động trên Apple silicon</summary>

```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
  grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
  --predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
  echo '[*] Apple silicon LocalPolicy (read-only display):'
  bputil -d -j 2>&1
fi
```

</details>



## References

- [1] [Hướng dẫn bảo mật nền tảng Apple — Quy trình khởi động](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Bản cập nhật bảo mật Apple — CVE liên quan đến NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Bảo mật Apple T2](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Bảo mật nền tảng Apple — Nội dung của tệp LocalPolicy trên máy Mac dùng Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Vượt xa LaunchAgents quen thuộc — Duy trì hiện diện qua NVRAM bằng apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
