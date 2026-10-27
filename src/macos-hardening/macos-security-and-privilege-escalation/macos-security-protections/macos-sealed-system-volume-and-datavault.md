# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Thông tin cơ bản

Bắt đầu từ **macOS Big Sur (11.0)**, system volume được niêm phong bằng mật mã thông qua **cây băm snapshot APFS**. Tính năng này được gọi là **Sealed System Volume (SSV)**. Phân vùng hệ thống được gắn kết ở chế độ **chỉ đọc**; mọi sửa đổi đều phá vỡ niêm phong, và trạng thái này được xác minh trong quá trình khởi động.<sup>[[11]](#references)</sup>

SSV cung cấp:
- **Phát hiện giả mạo** — mọi sửa đổi đối với system binary/framework đều làm thay đổi gốc cây Merkle và khiến niêm phong do Apple ký không còn hợp lệ
- **Xác thực lúc khởi động** — chuỗi khởi động xác minh snapshot hệ thống được chọn trước khi snapshot đó trở thành root filesystem
- **Khả năng chống rootkit** — ngay cả root cũng không thể thay thế lâu dài các tệp trong snapshot hệ thống đã xác thực nếu không tắt authenticated root hoặc xâm phạm một đường dẫn cập nhật được ủy quyền

SSV bảo vệ volume **System**, chứ không phải volume **Data** có thể ghi được ghép cặp với nó. Firmlinks hợp nhất cả hai volume vào namespace hiển thị tại `/`, vì vậy một đường dẫn trông có vẻ ghi được không chứng minh rằng đối tượng bên dưới thuộc về snapshot đã niêm phong. FileVault và Data Protection bảo vệ tính bí mật của dữ liệu khi lưu trữ; chúng tách biệt với tính toàn vẹn của SSV.<sup>[[11]](#references)</sup>

### Kiểm tra trạng thái SSV

```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / " 

# Show the volume group and the current Sealed field
diskutil apfs listVolumeGroups
diskutil apfs list | grep -B 8 -A 8 'Sealed:'
```

### Góc nhìn hệ thống thực tế: SSV + Cryptex grafts

Trong các bản phát hành macOS gần đây, không phải mọi tệp thực thi hiển thị bên dưới `/System` đều nhất thiết đến từ snapshot SSV đã khởi động. **Cryptexes** là các disk image APFS được xác thực riêng, với nội dung được graft lên các thư mục được chọn; do đó, Rapid Security Responses có thể thay thế các thành phần nhạy cảm về bảo mật mà không cần dựng lại SSV cơ sở. Khi điều tra persistence hoặc diff mã hệ thống, hãy kiểm kê các mount đang hoạt động và kho Cryptex trong Preboot, thay vì chỉ hash snapshot cơ sở:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

Chuỗi khởi động và thông tin chi tiết về Rapid Security Response được trình bày trong [Kiến trúc macOS — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); phần này tập trung vào ranh giới của SSV.

### Entitlement của SSV Writer

Một số binary hệ thống của Apple có entitlement cho phép chúng sửa đổi hoặc quản lý sealed system volume:

| Entitlement | Mục đích |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Khôi phục system volume về snapshot trước đó |
| `com.apple.private.apfs.create-sealed-snapshot` | Tạo sealed snapshot mới sau các bản cập nhật hệ thống |
| `com.apple.rootless.install.heritable` | Ghi vào các đường dẫn được SIP bảo vệ (được tiến trình con kế thừa) |
| `com.apple.rootless.install` | Ghi vào các đường dẫn được SIP bảo vệ |

### Tìm các SSV Writer

```bash
# Search for binaries with SSV-related entitlements
find /System /usr -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "apfs.revert-to-snapshot\|apfs.create-sealed-snapshot\|rootless.install" && echo "{}"
' \; 2>/dev/null

# Using the scanner database
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'ssv_writer';"
```

### Kịch bản tấn công

#### Snapshot Rollback Attack

Nếu kẻ tấn công xâm phạm một binary có `com.apple.private.apfs.revert-to-snapshot`, họ có thể **khôi phục system volume về trạng thái trước khi cập nhật**, khôi phục các lỗ hổng đã biết:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Rollback snapshot thực chất **hoàn tác các bản cập nhật bảo mật**, khôi phục những lỗ hổng kernel và hệ thống đã được vá trước đó. Đây là một trong những thao tác nguy hiểm nhất có thể thực hiện trên các phiên bản macOS hiện đại.

#### Thay thế tệp nhị phân hệ thống

Khi kết hợp bypass SIP + khả năng ghi vào SSV, kẻ tấn công có thể:

1. Gắn kết system volume ở chế độ đọc-ghi
2. Thay thế một system daemon hoặc thư viện framework bằng phiên bản chứa trojan
3. Niêm phong lại snapshot (hoặc chấp nhận seal bị hỏng nếu SIP đã suy yếu)
4. Rootkit tồn tại qua các lần khởi động lại và không thể bị các công cụ phát hiện ở userland phát hiện

### Các CVE ngoài thực tế

| CVE | Mô tả |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass SIP bằng cách khai thác entitlement `com.apple.rootless.install.heritable` của `system_installd` để chạy các post-install script tùy ý ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Bypass SIP: `system_installd` đặt post-install script trong một thư mục được SIP bảo vệ bên dưới `/tmp`, nhưng bản thân `/tmp` không được SIP bảo vệ, vì vậy có thể thay thế thư mục đó bằng cách gắn kết một image lên trên nó ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write trong XNU cho phép ghi vào các tệp chỉ đọc do root sở hữu ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Thông tin cơ bản

**DataVault** là cơ chế bảo vệ filesystem dựa trên entitlement dành cho các tệp và thư mục nhạy cảm. BSD flag `UF_DATAVAULT` (`0x00000080`) đánh dấu một đối tượng là cần entitlement để đọc và ghi; không giống DAC thông thường, việc chỉ trở thành **root** hoặc được cấp Full Disk Access không đáp ứng yêu cầu này khi cơ chế bảo vệ đang được thực thi.<sup>[[4]](#references)[[13]](#references)</sup>

Không nên dùng “DataVault” như từ đồng nghĩa cho mọi database được bảo vệ. Các database TCC được quản lý bằng chính sách dành riêng cho TCC/FDA và SIP (xem [macOS TCC](macos-tcc/README.md)), trong khi quyền truy cập vào các mục keychain còn phụ thuộc vào Keychain ACL và cơ chế bảo vệ bằng mật mã (xem [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Các ví dụ DataVault thực tế thường xuất hiện dưới dạng kho lưu trữ do service sở hữu bên dưới `/private/var/folders/.../0/`, chẳng hạn như kho lưu trữ Screen Time; flag này hiển thị là `datavault` trong BSD file flags khi có thể stat thư mục cha.

### Entitlement của DataVault Controller

| Entitlement | Phạm vi |
|---|---|
| `com.apple.rootless.datavault.controller` | Truy cập/quản lý các đối tượng `UF_DATAVAULT`<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Quản lý các quyết định TCC; đây là ranh giới quyền riêng tư có liên quan nhưng tách biệt |
| `com.apple.private.tcc.allow` | Bypass các dịch vụ TCC được chọn, nêu trong giá trị entitlement |
| `com.apple.rootless.storage.TCC` | Ghi vào kho lưu trữ TCC được SIP bảo vệ |

Một process kết hợp entitlement DataVault-controller với chức năng FDA, backup, indexing hoặc IPC đặc biệt đáng chú ý: hãy tìm primitive confused-deputy sao chép một đối tượng được bảo vệ sang một đường dẫn thông thường, thay vì cố mở vault trực tiếp.<sup>[[14]](#references)</sup>

### Tìm DataVault Controller

```bash
# BSD flags: a protected object is printed with the `datavault` keyword
ls -ldeO@ /private/var/folders/*/*/0/com.apple.ScreenTimeAgent 2>/dev/null
sudo find /private/var/folders -flags +datavault -print 2>/dev/null

# Find Apple binaries carrying DataVault/TCC controller entitlements
find /System /usr -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "datavault.controller\|private.tcc\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```

### Các kịch bản tấn công

#### Sửa đổi trực tiếp cơ sở dữ liệu TCC (ranh giới TCC riêng biệt)

Nếu kẻ tấn công xâm phạm một tiến trình quản lý TCC (ví dụ: bằng cách chèn mã vào tiến trình có `com.apple.private.tcc.manager`), họ có thể **sửa đổi trực tiếp cơ sở dữ liệu TCC** để cấp bất kỳ quyền TCC nào cho bất kỳ ứng dụng nào:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> Việc sửa đổi cơ sở dữ liệu TCC là **cách vượt qua quyền riêng tư triệt để nhất** — nó âm thầm cấp mọi quyền mà không hiển thị lời nhắc hay dấu hiệu nào cho người dùng. Trong lịch sử, nhiều chuỗi leo thang đặc quyền trên macOS đã kết thúc bằng việc ghi vào cơ sở dữ liệu TCC như payload cuối cùng.

#### Truy cập cơ sở dữ liệu Keychain

Truy cập thô vào cơ sở dữ liệu nền của keychain không đồng nghĩa với việc có thể truy cập bí mật ở dạng văn bản thuần. Nếu một ranh giới đặc quyền khác cho phép kẻ tấn công sao chép cơ sở dữ liệu, thì vẫn phải tấn công khóa mật mã và ACL của các mục; hãy xem trang [macOS Keychain](../../macos-red-teaming/macos-keychain.md) chuyên biệt thay vì cho rằng entitlement DataVault-controller là đủ.

#### Ranh giới bản sao lưu: Time Machine

Một phân tích năm 2026 đã chứng minh một mô hình tổng quát hữu ích: `backupd` có cả `com.apple.rootless.datavault.controller` lẫn Full Disk Access để có thể sao chép các kho dữ liệu được bảo vệ. Trên cấu hình được thử nghiệm, `/private/var/folders` nằm trong phạm vi sao lưu của Time Machine và bản sao lưu được mount không thực thi ranh giới DataVault đang áp dụng cho dữ liệu trực tiếp. Nhà nghiên cứu đã dùng cách này để xác định vị trí cơ sở dữ liệu SQLite của Screen Time và đọc mã PIN giới hạn ở dạng văn bản thuần mà không mở kho dữ liệu trực tiếp. Hãy xem đây là một **tấn công qua ranh giới bản sao**: rà soát các tiến trình phụ trách sao lưu, xuất dữ liệu, di chuyển, lập chỉ mục và chẩn đoán có thể đưa dữ liệu trong vault ra dưới một điểm mount hoặc đường dẫn ít bị hạn chế hơn.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

Hành vi này phụ thuộc vào phiên bản và bố cục bản sao lưu. Hãy xác minh trên bản build mục tiêu và nhớ rằng đích Time Machine được mã hóa chỉ bảo vệ bản sao khi ổ đĩa đang khóa; khi đã được gắn kết, các quyền truy cập của nó trở thành một phần của bề mặt tấn công.

### Các CVE ngoài thực tế liên quan đến bypass DataVault/TCC

| CVE | Mô tả |
|---|---|
| CVE-2024-44131 | Lỗi race symlink trong FileProvider cho phép một helper có đặc quyền truy cập dữ liệu được TCC bảo vệ ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Với quyền root, **tạo người dùng mới có `NFSHomeDirectory` trỏ đến `TCC.db` do kẻ tấn công kiểm soát**; khi đăng nhập, `tccd` sử dụng tệp này và áp dụng các quyền đã cấp, qua đó truy cập dữ liệu của người dùng khác ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": thay đổi thư mục home của người dùng để cài `TCC.db` do kẻ tấn công kiểm soát ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Lỗi xác định bundle cho phép ứng dụng **kế thừa các quyền TCC của một bundle khác** mà không cần hỏi người dùng; **XCSSET** đã khai thác lỗi này ngoài thực tế để chụp ảnh màn hình desktop ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` dựng đường dẫn DB từ `$HOME`, vì vậy `launchctl setenv HOME` chuyển hướng nó đến `TCC.db` do kẻ tấn công kiểm soát ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` có `com.apple.private.tcc.manager` **và** tắt library validation, vì vậy một HAL plug-in được đặt trong `/Library/Audio/Plug-Ins/HAL` có thể cấp mọi quyền TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft phát hiện lỗ hổng macOS mới Shrootless, có thể bypass System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Phân tích kỹ thuật: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Làm dở còn hơn không làm](https://worthdoingbadly.com/macdirtycow/)
- [4] [Bảo mật nền tảng Apple — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass đánh cắp dữ liệu từ iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Vạch trần malware macOS: Bypass TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Lỗ hổng macOS mới "powerdir" có thể dẫn đến truy cập trái phép dữ liệu người dùng](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Phát hiện TCC bypass zero-day trong malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Bypass framework Transparency, Consent, and Control (TCC) của macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Phát nhạc và bypass TCC, hay CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Cơn ác mộng về các bản cập nhật OTA của Apple (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — Khai thác TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Cách bypass mật mã Screen Time của chính bạn — phân tích mã nguồn và Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
