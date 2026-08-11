# ZIP 文件技巧

{{#include ../../../banners/hacktricks-training.md}}

用于管理 **zip 文件**的**命令行工具**对于诊断、修复和破解 zip 文件至关重要。以下是一些关键工具：<sup>[[1]](#references)</sup>

- **`unzip`**：揭示 zip 文件无法解压的原因。
- **`zipdetails -v`**：详细分析 zip 文件格式字段。<sup>[[3]](#references)</sup>
- **`zipinfo`**：列出 zip 文件的内容而不进行解压。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的 zip 文件。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：用于暴力破解 zip 密码的工具，对长度约 7 个字符以内的密码较为有效。

[Zip 文件格式规范](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)全面介绍了 zip 文件的结构和标准。<sup>[[4]](#references)</sup>

需要注意的是，传统的受密码保护的 ZIP 文件通常会暴露文件名和文件大小，这不同于 RAR 和 7z 支持的 header-encryption 模式。此外，如果存在压缩文件的未加密副本，使用较旧 ZipCrypto 方法加密的 ZIP 文件容易受到 **plaintext attack** 的攻击。<sup>[[1]](#references)</sup> 此攻击利用已知内容来破解 ZIP 密码，具体说明见[这篇学术论文](https://math.ucr.edu/~mike/zipattacks.pdf)，并在[这个 Hack This Site walk-through](https://www.hackthissite.org/articles/read/793)中进行了演示。<sup>[[11]](#references)[[12]](#references)</sup> 但是，ZipCrypto known-plaintext attack 不适用于使用 **AES-256** 加密保护的条目。<sup>[[1]](#references)</sup>

---

## 使用被操纵的 ZIP headers 规避 APK 中的逆向分析

现代 Android malware dropper 使用格式错误的 ZIP 元数据来破坏静态工具（jadx/apktool/unzip）的运行，同时保持 APK 可以在设备上安装。最常见的技巧包括：<sup>[[2]](#references)</sup>

- 通过设置 ZIP General Purpose Bit Flag（GPBF）的 bit 0 来伪造加密
- 滥用大型/自定义 Extra 字段来混淆解析器
- 文件/目录名称冲突，用于隐藏真实 artifact（例如，在真正的 `classes.dex` 旁边放置一个名为 `classes.dex/` 的目录）

### 1) 设置 GPBF bit 0 的伪造加密，不使用真正的 crypto

现象：
- `jadx-gui` 失败并显示类似以下错误：

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` 会提示输入核心 APK 文件的密码，即使有效 APK 不可能对 `classes*.dex`、`resources.arsc` 或 `AndroidManifest.xml` 进行加密：

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
查看本地标头和中央标头中的 General Purpose Bit Flag。一个明显的值是即使对于核心条目，位 0 也被设置（Encryption）：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
启发式判断：如果 APK 可以在设备上安装并运行，但工具显示核心条目为“encrypted”，则说明 GPBF 被篡改。

修复方法是清除 Local File Headers (LFH) 和 Central Directory (CD) 条目中的 GPBF bit 0。最小化的字节修补器：

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

### 2) 使用大型/自定义 Extra fields 破坏 parsers

攻击者会在 headers 中填充超大的 Extra fields 和异常的 IDs，以干扰 decompilers。在实际环境中，你可能会看到嵌入其中的自定义 markers（例如类似 `JADXBLOCK` 的 strings）。

检查：
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
观察到的示例：携带大型 payload 的未知 ID，如 `0xCAFE`（"Java Executable"）或 `0x414A`（"JA:"）。<sup>[[2]](#references)</sup>

DFIR 启发式规则：
- 当核心条目（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）中的 Extra 字段异常大时发出警报。
- 将这些条目上的未知 Extra ID 视为可疑。

实用缓解措施：重建 archive（例如，将提取出的文件重新打包为 zip）会移除恶意 Extra 字段。如果工具因伪造的加密而拒绝提取，请先按上述方法清除 GPBF bit 0，然后重新打包：
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 文件/目录名称冲突（隐藏真实 artifact）

ZIP 可以同时包含文件 `X` 和目录 `X/`。某些提取器和反编译器会因此混淆，可能使用目录条目覆盖或隐藏真实文件。已观察到条目与 `classes.dex` 等核心 APK 名称发生冲突。

分类检查和安全提取：
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
蓝队检测思路：
- 标记本地头将加密标记为（GPBF bit 0 = 1）但仍能安装/运行的 APK。
- 标记核心条目上较大或未知的 Extra fields（查找类似 `JADXBLOCK` 的标记）。
- 专门针对 `AndroidManifest.xml`、`resources.arsc`、`classes*.dex` 检测路径冲突（`X` 和 `X/`）。

---

## 其他恶意 ZIP tricks（2024–2026）

### 拼接的 central directories（multi-EOCD evasion）

在 2024 年的一次 phishing campaign 中，攻击者发送了一个实际上由**两个拼接在一起的 ZIP 文件**组成的单一 blob。每个文件都有自己的 End of Central Directory（EOCD）record 和 central directory。不同的 extractor 会解析不同的 directory（7-Zip 读取第一个，而 WinRAR 读取最后一个），使攻击者能够隐藏只有部分工具可见的 payload；仅检查一个 directory 的 scanner 可能会漏掉另一个 archive。<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
如果出现多个 EOCD，或出现“data after payload”警告，请拆分该 blob 并检查每个部分：
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs（non-recursive）

Quoted-overlap ZIP bombs 构建一个微小的 **kernel**（高度压缩的 DEFLATE block），并在多个重叠的 entries 之间复用它。Full-overlap variants 将多个 central-directory entries 指向同一个 local header，而 quoted-overlap variants 则在 DEFLATE streams 中引用 local headers；该 published construction 在不使用 nested archives 的情况下实现了超过 28M:1 的压缩比。<sup>[[7]](#references)</sup>

**Quick detection（duplicate LFH offsets）**
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
- 执行试运行遍历：`zipdetails -v file.zip | grep -n "Local Header Offset"`，并比较所引用的 local-header 偏移量和压缩数据范围；重复偏移量表示存在完全重叠的变体。<sup>[[7]](#references)[[8]](#references)</sup>
- 在提取前，使用 parser 限制允许的总 uncompressed size 和 entry 数量；`zipinfo -t file.zip` 会报告总数，但不会强制执行安全限制。<sup>[[8]](#references)</sup>
- 必须提取时，应在具有 CPU 和磁盘限制的 cgroup/VM 中执行（避免无界膨胀导致崩溃）。<sup>[[8]](#references)</sup>

---

### Local-header 与 central-directory parser 混淆

近期的 differential-parser 研究表明，ZIP ambiguity 在现代 toolchain 中仍然可以被利用。核心思想很简单：某些软件信任 **Local File Header (LFH)**，而其他软件信任 **Central Directory (CD)**，因此同一个 archive 可以向不同工具呈现不同的文件名、路径、注释、偏移量或 entry 集合。<sup>[[9]](#references)</sup>

实际 offensive 用途：
- 让 upload filter、AV pre-scan 或 package validator 在 CD 中看到 benign file，而 extractor 遵循不同 LFH 中的名称/路径。
- 利用 duplicate names、仅存在于某一结构中的 entries，或存在歧义的 Unicode path metadata（例如 Info-ZIP Unicode Path Extra Field `0x7075`），使不同 parser 重建出不同的目录树。
- 将其与 path traversal 结合，把看似“无害”的 archive view 转化为提取过程中的 write-primitive。关于 extraction 侧，请参阅 [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)。

DFIR 分析：
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
请提供需要翻译的英文内容。
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
启发式方法：
- 对于安全敏感的 ingestion，拒绝或隔离 LFH/CD 名称不匹配、文件名重复、包含多个 EOCD 记录，或最终 EOCD 后存在尾随字节的 archives。<sup>[[9]](#references)[[10]](#references)</sup>
- 如果不同工具对提取出的文件树得出不同结果，则应将使用异常 Unicode-path extra fields 或不一致 comments 的 ZIP 视为可疑。<sup>[[4]](#references)[[9]](#references)</sup>
- 如果分析比保留原始字节更重要，请在 sandbox 中提取后，使用严格的 parser 重新打包 archive，并将生成的文件列表与原始 metadata 进行比较。

这不仅适用于 package ecosystems：同一类歧义也可能从 mail gateways、static scanners 以及 custom ingestion pipelines 中隐藏 payload。这些系统会先“查看”ZIP 内容，再交由不同的 extractor 处理 archive。<sup>[[9]](#references)</sup>

---



## References

- [1] [CTF Forensics Field Guide（Mike's Blog，CTF 分类）](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – 第 1 部分 – 多阶段 dropper（APK ZIP anti-reversing）](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails（IO::Compress script）](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP 文件格式规范（PKWARE APPNOTE.TXT）](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [利用 ZIP archives 的灵活结构隐藏 malware 且不被检测（Perception Point）](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers 将 malware 藏入新的 ZIP file attack —— 拼接的 ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [更好的 zip bomb（David Fifield，USENIX WOOT 2019）](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [理解 Zip Bombs：overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [我的 ZIP 不是你的 ZIP：识别并利用 ZIP parsers 之间的语义差异（USENIX Security 2025）](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [防止针对 Python package installers 的 ZIP parser confusion attacks](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [使用减少的已知明文进行 ZIP Attacks（Michael Stay，AccessData Corporation）](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site：Realistic Web Mission，第 15 关（known-plaintext ZIP attack）](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
