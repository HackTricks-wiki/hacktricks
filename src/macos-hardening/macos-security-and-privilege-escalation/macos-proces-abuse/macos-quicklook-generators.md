# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

Quick Look là **framework xem trước file** của macOS. Khi người dùng chọn một file trong Finder, nhấn Space, di chuột lên file hoặc xem một thư mục khi đã bật hình thu nhỏ, Quick Look sẽ **tự động tải một plugin generator** để phân tích file và hiển thị bản xem trước trực quan.<sup>[[1]](#references)</sup>

Quick Look generators là các **bundle** (`.qlgenerator`) đăng ký xử lý những **Uniform Type Identifiers (UTIs)** cụ thể. Khi macOS cần xem trước một file khớp với UTI đó, hệ thống sẽ tải generator vào một tiến trình trợ giúp sandbox (`QuickLookSatellite` hoặc `qlmanage`) rồi gọi hàm generator của nó.

### Vì sao điều này quan trọng đối với bảo mật

> [!WARNING]
> Quick Look generators được kích hoạt khi người dùng **chỉ cần chọn hoặc xem một file** — không cần thao tác "Open". Điều này biến chúng thành một **vector khai thác thụ động** mạnh mẽ: người dùng chỉ cần mở một thư mục có chứa file độc hại.

**Bề mặt tấn công:**
- Generators **phân tích nội dung file tùy ý** từ ổ đĩa, nội dung tải xuống, tệp đính kèm email hoặc network share
- Một file được tạo có chủ đích có thể khai thác **lỗ hổng phân tích** (buffer overflow, format string, type confusion) trong mã generator
- Việc hiển thị bản xem trước diễn ra **tự động** — chỉ cần xem thư mục Downloads nơi có file độc hại là đủ
- Quick Look chạy trong một **tiến trình trợ giúp sandbox**, nhưng các trường hợp thoát sandbox từ bối cảnh này đã được chứng minh

## Kiến trúc

```
User selects file in Finder
        ↓
Finder → QuickLookSatellite (sandboxed helper)
        ↓
Generator plugin loaded (.qlgenerator bundle)
        ↓
Plugin parses file content → Returns preview image/HTML
        ↓
Preview displayed to user
```

## Trinh sát

### Liệt kê các Generator đã cài đặt

```bash
# List all Quick Look generators with their UTI registrations
qlmanage -m plugins 2>&1

# Find generator bundles on the system
find / -name "*.qlgenerator" -type d 2>/dev/null

# Common locations
ls /Library/QuickLook/
ls ~/Library/QuickLook/
ls /System/Library/QuickLook/

# Check a generator's Info.plist for UTI registrations
defaults read /path/to/Generator.qlgenerator/Contents/Info.plist 2>/dev/null
```

### Sử dụng Scanner

```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```

## Kịch bản tấn công

### Khai thác dựa trên tệp

Một Quick Look generator của bên thứ ba phân tích các định dạng tệp phức tạp (mô hình 3D, dữ liệu khoa học, định dạng lưu trữ) là mục tiêu hàng đầu:

```bash
# 1. Identify a third-party generator and its UTI
qlmanage -m plugins 2>&1 | grep -v "com.apple" | head -20

# 2. Find what file types it handles
defaults read /Library/QuickLook/SomeGenerator.qlgenerator/Contents/Info.plist \
  CFBundleDocumentTypes 2>/dev/null

# 3. Craft a malicious file matching that UTI
# (fuzzer output or hand-crafted malformed file)

# 4. Place the file where the user will preview it
cp malicious.xyz ~/Downloads/

# 5. When user opens Downloads in Finder → preview triggers → exploit fires
```

### Drive-By qua Downloads

```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```

### Thay thế Generator của bên thứ ba

Nếu một bundle Quick Look generator được cài đặt tại **vị trí người dùng có thể ghi** (`~/Library/QuickLook/`), nó có thể bị thay thế:

```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```

### Kích hoạt Quick Look từ xa

```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```

## Các cân nhắc về Sandbox

Quick Look generators chạy bên trong một helper process bị sandbox. Hồ sơ sandbox giới hạn:
- Quyền truy cập hệ thống tệp (hầu hết chỉ đọc tệp đang được xem trước)
- Quyền truy cập mạng (bị hạn chế)
- IPC (mach-lookup bị giới hạn)

Tuy nhiên, sandbox có các vector thoát đã được biết đến:

```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```

## CVE thực tế<sup>[[2]](#references)</sup>

| CVE | Mô tả |
|---|---|
| CVE-2019-8741 | Lỗi hỏng bộ nhớ trong bản xem trước Quick Look qua tệp được tạo thủ công |
| CVE-2018-4293 | Thoát sandbox của trình tạo Quick Look |
| CVE-2020-9963 | Tiết lộ thông tin trong quá trình xử lý bản xem trước Quick Look |
| CVE-2021-30876 | Lỗi hỏng bộ nhớ trong quá trình tạo hình thu nhỏ |

## Fuzzing Quick Look Generators

```bash
# Basic fuzzing approach for a Quick Look generator:

# 1. Identify the target generator and its file format
qlmanage -m plugins 2>&1 | grep "target-uti"

# 2. Collect seed corpus of valid files
find / -name "*.targetext" -size -1M 2>/dev/null | head -100

# 3. Mutate files and trigger preview
for f in /tmp/fuzz_corpus/*; do
  # Mutate the file (using radamsa, honggfuzz, etc.)
  radamsa "$f" > /tmp/fuzz_input.targetext
  
  # Trigger Quick Look (with timeout to catch hangs)
  timeout 5 qlmanage -t /tmp/fuzz_input.targetext 2>&1
  
  # Check if QuickLookSatellite crashed
  log show --last 5s --predicate 'process == "QuickLookSatellite" AND eventMessage CONTAINS "crash"' 2>/dev/null
done
```

## References

- [1] [Apple Developer — Hướng dẫn lập trình Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Bản cập nhật bảo mật của Apple — CVE về Quick Look](https://support.apple.com/en-us/HT201222)
{{#include ../../../banners/hacktricks-training.md}}
