# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

Quick Look 是 macOS 的**文件预览框架**。当用户在 Finder 中选择文件、按下空格键、将鼠标悬停在文件上，或查看启用了缩略图的目录时，Quick Look 会**自动加载 generator plugin**，解析文件并渲染可视化预览。<sup>[[1]](#references)</sup>

Quick Look generators 是注册到特定 **Uniform Type Identifiers (UTIs)** 的 **bundles**（`.qlgenerator`）。当 macOS 需要预览与该 UTI 匹配的文件时，它会将 generator 加载到 sandboxed helper process（`QuickLookSatellite` 或 `qlmanage`）中，并调用其 generator function。

### 为什么这对安全很重要

> [!WARNING]
> Quick Look generators 只需用户**选择或查看文件**即可触发——无需执行“Open”操作。这使其成为一种强大的**被动 exploitation vector**：用户只需进入包含恶意文件的目录即可。

**攻击面：**
- Generators 会从磁盘、downloads、email attachments 或 network shares 中**解析任意文件内容**
- 精心构造的文件可以利用 generator code 中的**解析漏洞**（buffer overflows、format strings、type confusion）
- Preview rendering 会**自动进行**——查看存放了恶意文件的 Downloads 文件夹就已足够
- Quick Look 在 **sandboxed helper** 中运行，但已经有从该上下文中实现 sandbox escapes 的案例

## 架构
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
## 枚举

### 列出已安装的 Generators
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
### 使用 Scanner
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## 攻击场景

### 基于文件的利用

解析复杂文件格式（3D 模型、科学数据、归档格式）的第三方 Quick Look generator 是理想的目标：
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
### 通过 Downloads 的 Drive-By
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### 第三方 Generator 替换

如果 Quick Look generator bundle 安装在**用户可写入的位置**（`~/Library/QuickLook/`），则可以将其替换：
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### 远程触发 Quick Look
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Sandbox 注意事项

Quick Look generators 在 sandboxed helper process 中运行。sandbox profile 限制了：
- 文件系统访问（主要为只读，仅限于正在预览的文件）
- 网络访问（受限）
- IPC（受限的 mach-lookup）

不过，sandbox 存在已知的逃逸路径：
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## 真实世界中的 CVE

| CVE | 描述 |
|---|---|
| CVE-2019-8741 | 通过构造的文件导致 Quick Look 预览内存破坏 |
| CVE-2018-4293 | Quick Look generator 沙箱逃逸 |
| CVE-2020-9963 | Quick Look 预览处理导致信息泄露 |
| CVE-2021-30876 | 缩略图生成过程中的内存破坏 |

## 对 Quick Look Generators 进行 Fuzzing
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
## 参考资料

- [1] [Apple Developer — Quick Look 编程指南](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple 安全更新 — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Objective-See — Quick Look 攻击面](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
