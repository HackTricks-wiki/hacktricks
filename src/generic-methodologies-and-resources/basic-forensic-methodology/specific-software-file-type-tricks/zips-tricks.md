# ZIPs 技巧

用于管理 **zip files** 的 **命令行工具** 对诊断、修复和破解 zip files 至关重要。以下是一些关键工具：<sup>[[1]](#references)</sup>

- **`unzip`**：揭示 zip file 可能无法解压的原因。
- **`zipdetails -v`**：对 zip file 格式字段进行详细分析。<sup>[[3]](#references)</sup>
- **`zipinfo`**：列出 zip file 的内容，而无需提取它们。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的 zip files。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：用于 brute-force 破解 zip passwords 的工具，对长度约为 7 个字符以内的 passwords 有效。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) 提供了有关 zip files 结构和标准的全面细节。<sup>[[4]](#references)</sup>

需要特别注意的是，传统的 password-protected ZIP files 通常会暴露 filenames 和 file sizes，这不同于 RAR 和 7z 支持的 header-encryption 模式。此外，如果存在某个 compressed file 的 unencrypted 副本，使用旧版 ZipCrypto method 加密的 ZIP files 容易受到 **plaintext attack** 的攻击。<sup>[[1]](#references)</sup> 这种攻击利用已知内容来破解 ZIP 的 password，具体说明见[这篇 academic paper](https://math.ucr.edu/~mike/zipattacks.pdf)，示例见[这个 Hack This Site walk-through](https://www.hackthissite.org/articles/read/793)。<sup>[[11]](#references)[[12]](#references)</sup> 但是，ZipCrypto known-plaintext attack 不适用于使用 **AES-256** encryption 保护的 entries。<sup>[[1]](#references)</sup>

---

## 使用经过篡改的 ZIP headers 在 APKs 中实施 anti-reversing tricks

现代 Android malware droppers 会使用格式异常的 ZIP metadata 来破坏静态工具（jadx/apktool/unzip）的工作，同时保持 APK 能够在设备上安装。最常见的 tricks 包括：<sup>[[2]](#references)</sup>

- 通过设置 ZIP General Purpose Bit Flag (GPBF) bit 0 来伪造 encryption
- 滥用大型或自定义的 Extra fields 来干扰 parsers
- 利用 file/directory name collisions 隐藏真实 artifacts（例如，在真实的 `classes.dex` 旁边放置一个名为 `classes.dex/` 的 directory）

### 1) Fake encryption（设置 GPBF bit 0），但不使用真正的 crypto

症状：
- `jadx-gui` 失败，并显示类似以下错误：

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` 会要求输入 core APK files 的 password，尽管有效的 APK 不可能对 `classes*.dex`、`resources.arsc` 或 `AndroidManifest.xml` 进行 encrypted：

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

使用 zipdetails 检测：
```bash
zipdetails -v sample.apk | less
```
查看本地和中央 headers 的 General Purpose Bit Flag。一个明显的特征是，即使对于核心条目，bit 0 也被设置（Encryption）：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
启发式判断：如果某个 APK 能在设备上安装并运行，但其核心条目在工具中显示为“encrypted”，则说明 GPBF 被篡改了。

通过清除 Local File Headers (LFH) 和 Central Directory (CD) 条目中的 GPBF bit 0 进行修复。最小化 byte-patcher：

<details>
<summary>最小化 GPBF bit-clear patcher</summary>
```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
out = bytearray(buf)
i = 0
patched = 0
while True:
i = out.find(sig, i)
if i == -1:
break
flags, = struct.unpack_from('<H', out, i + flag_off)
if flags & 1:  # encryption bit set
struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
patched += 1
i += 4  # move past signature to continue search
return bytes(out), patched

if __name__ == '__main__':
inp, outp = sys.argv[1], sys.argv[2]
data = open(inp, 'rb').read()
data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
open(outp, 'wb').write(data)
print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```
</details>

用法：
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
You should now see `General Purpose Flag  0000` on core entries and tools will parse the APK again.

### 2) Large/custom Extra fields to break parsers

攻击者会在 headers 中填充超大的 Extra fields 和异常 ID，以干扰反编译器。在实际环境中，你可能会看到嵌入其中的自定义标记（例如类似 `JADXBLOCK` 的字符串）。

检查：
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
观察到的示例：携带大型 payload 的未知 ID，例如 `0xCAFE`（"Java Executable"）或 `0x414A`（"JA:"）。<sup>[[2]](#references)</sup>

DFIR 启发式规则：
- 当核心条目（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）中的 Extra fields 异常大时发出警报。
- 将这些条目上的未知 Extra IDs 视为可疑。

实用缓解措施：重建 archive（例如重新压缩提取出的文件）会移除恶意 Extra fields。如果工具因伪造的 encryption 而拒绝提取，先按上述方法清除 GPBF bit 0，然后重新打包：
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 文件/目录名称冲突（隐藏真实 artifacts）

ZIP 可以同时包含文件 `X` 和目录 `X/`。某些解压工具和反编译器会因此混淆，可能使用目录条目覆盖或隐藏真实文件。已观察到条目与 `classes.dex` 等核心 APK 名称发生冲突的情况。

分流与安全解压：
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
修复后的程序化检测：
```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
names = z.namelist()

collisions = defaultdict(list)
for n in names:
base = n[:-1] if n.endswith('/') else n
collisions[base].append(n)

for base, variants in collisions.items():
if len(variants) > 1:
print('COLLISION', base, '->', variants)
```
Blue-team 检测思路：
- 标记本地 headers 标记为加密（GPBF bit 0 = 1）但仍能安装/运行的 APK。
- 标记核心 entries 上较大或未知的 Extra fields（查找类似 `JADXBLOCK` 的 markers）。
- 专门标记 `AndroidManifest.xml`、`resources.arsc`、`classes*.dex` 的路径冲突（`X` 和 `X/`）。

---

## 其他恶意 ZIP tricks（2024–2026）

### 拼接的 central directories（multi-EOCD evasion）

在 2024 年的一次 phishing campaign 中，攻击者发送了一个实际上由**两个拼接在一起的 ZIP files**组成的单一 blob。每个文件都有自己的 End of Central Directory（EOCD）record 和 central directory。不同的 extractors 会解析不同的 directory（7-Zip 读取第一个，而 WinRAR 读取最后一个），从而使攻击者能够隐藏只有部分 tools 才能显示的 payloads；只检查一个 directory 的 scanners 可能会漏掉另一个 archive。<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
如果出现多个 EOCD，或有“data after payload”警告，请拆分该 blob 并检查每个部分：
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs（非递归）

Quoted-overlap ZIP bombs 构建一个微小的 **kernel**（高度压缩的 DEFLATE block），并在重叠的 entries 之间重复使用它。Full-overlap 变体让多个 central-directory entries 指向同一个 local header，而 quoted-overlap 变体则在 DEFLATE streams 内引用 local headers；公开的构造无需嵌套 archives，即可实现超过 28M:1 的压缩比。<sup>[[7]](#references)</sup>

**快速检测（重复的 LFH offsets）**
```python
# detect full-overlap variants by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
i = buf.find(b'PK\x01\x02', off)
if i<0: break
rel = struct.unpack_from('<I', buf, i+42)[0]
if rel in seen:
print('OVERLAP at offset', rel)
break
seen.add(rel); off = i+4
```
**处理**
- 执行 dry-run 遍历：`zipdetails -v file.zip | grep -n "Local Header Offset"`，并比较所引用的 local-header 偏移量和压缩数据范围；重复的偏移量表示完全重叠的变体。<sup>[[7]](#references)[[8]](#references)</sup>
- 在提取前，使用 parser 限制允许的总解压大小和条目数量；`zipinfo -t file.zip` 会报告总数，但不会强制执行安全限制。<sup>[[8]](#references)</sup>
- 必须提取时，应在具备 CPU 和磁盘限制的 cgroup/VM 中执行（避免无界膨胀导致崩溃）。<sup>[[8]](#references)</sup>

---

### Local-header 与 central-directory parser 混淆

近期的 differential-parser 研究表明，ZIP 歧义在现代 toolchain 中仍可被利用。核心思路很简单：某些软件信任 **Local File Header (LFH)**，而另一些软件信任 **Central Directory (CD)**，因此同一个 archive 可以向不同工具呈现不同的文件名、路径、注释、偏移量或条目集合。<sup>[[9]](#references)</sup>

实际 offensive 用途：
- 使 upload filter、AV pre-scan 或 package validator 在 CD 中看到一个 benign 文件，而 extractor 则遵循不同的 LFH 名称/路径。
- 利用重复名称、仅存在于其中一种结构中的条目，或有歧义的 Unicode path metadata（例如 Info-ZIP Unicode Path Extra Field `0x7075`），使不同 parser 重建出不同的目录树。
- 将其与 path traversal 结合，把看似“无害”的 archive 视图转化为提取过程中的写入原语。关于提取侧，请参见 [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)。

DFIR 分诊：
```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
n, e = struct.unpack_from('<HH', b, i + 26)
lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
n = struct.unpack_from('<H', b, i + 28)[0]
off = struct.unpack_from('<I', b, i + 42)[0]
cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
if off in lfh and cd != lfh[off]:
print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
i += 4
```
补充内容：
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
启发式方法：
- 对于安全敏感的 ingestion，拒绝或隔离 LFH/CD 名称不匹配、文件名重复、存在多个 EOCD 记录，或最终 EOCD 后存在尾随字节的 archives。<sup>[[9]](#references)[[10]](#references)</sup>
- 如果不同工具对提取出的文件树产生不一致结果，则应将使用异常 Unicode-path extra fields 或不一致 comments 的 ZIP 视为可疑。<sup>[[4]](#references)[[9]](#references)</sup>
- 如果分析比保留原始字节更重要，则应在 sandbox 中提取后，使用 strict parser 重新打包 archive，并将生成的 file list 与原始 metadata 进行比较。

这不仅与 package ecosystems 有关：相同的歧义类别可以将 payloads 隐藏起来，使 mail gateways、static scanners 和 custom ingestion pipelines 受到影响；这些系统会在由其他 extractor 处理 archive 之前“窥探”ZIP 内容。<sup>[[9]](#references)</sup>

---



## References

- [1] [CTF Forensics Field Guide（Mike's Blog，CTF category）](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – 多阶段 dropper（APK ZIP anti-reversing）](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails（IO::Compress script）](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP 文件格式规范（PKWARE APPNOTE.TXT）](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [ZIP archives 的灵活结构被利用来隐藏 malware，使其不被检测到（Perception Point）](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers 将 malware 藏入新型 ZIP file attack —— 拼接的 ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [更好的 zip bomb（David Fifield，USENIX WOOT 2019）](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [理解 Zip Bombs：overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [我的 ZIP 不是你的 ZIP：识别并利用 ZIP parsers 之间的语义差异（USENIX Security 2025）](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [防止针对 Python package installers 的 ZIP parser confusion attacks](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [具有 reduced known plaintext 的 ZIP Attacks（Michael Stay，AccessData Corporation）](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site：Realistic Web Mission，第 15 关（known-plaintext ZIP attack）](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
