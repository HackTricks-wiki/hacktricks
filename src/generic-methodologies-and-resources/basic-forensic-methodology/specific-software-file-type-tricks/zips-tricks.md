# ZIPs 技巧

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** 用于管理 **zip files** 是诊断、修复和破解 **zip files** 的关键工具。下面是一些主要实用程序：

- **`unzip`**：用来揭示 zip 文件无法解压的原因。
- **`zipdetails -v`**：提供对 zip 文件格式字段的详细分析。
- **`zipinfo`**：列出 zip 文件的内容而不解压。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的 zip 文件。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：用于对 zip 密码进行暴力破解的工具，适用于大约 7 个字符以内的密码。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) 提供了关于 zip 文件结构和标准的全面细节。

需要注意的是，受密码保护的 **zip files** 并不会对内部的文件名或文件大小进行加密（**do not encrypt filenames or file sizes**），这是一个安全缺陷；RAR 或 7z 等格式可以加密这些信息。除此之外，使用旧的 ZipCrypto 方法加密的 zip 文件，如果存在未加密的压缩文件副本，则容易受到已知明文攻击（plaintext attack）。该攻击利用已知内容来破解 zip 密码，这一漏洞在 [HackThis 的文章](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) 和 [这篇学术论文](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) 中有详细说明。然而，使用 **AES-256** 加密的 zip 文件对这种明文攻击免疫，说明为敏感数据选择安全加密方法的重要性。

---

## 利用篡改的 ZIP headers 在 APK 中进行反逆向技巧

现代 Android 恶意软件 droppers 使用畸形的 ZIP 元数据来破坏静态工具（jadx/apktool/unzip），同时保持 APK 在设备上可安装。最常见的技巧包括：

- 通过设置 ZIP General Purpose Bit Flag (GPBF) 的 bit 0 来伪装加密
- 滥用大型/自定义 Extra 字段以混淆解析器
- 文件/目录名称冲突以隐藏真实痕迹（例如，在真实的 `classes.dex` 旁边创建一个名为 `classes.dex/` 的目录）

### 1) 伪装加密（设置 GPBF bit 0）但没有真正的加密

症状：
- `jadx-gui` 会报出类似的错误：

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` 会在核心 APK 文件上提示输入密码，尽管合法的 APK 不可能对 `classes*.dex`、`resources.arsc` 或 `AndroidManifest.xml` 进行加密：

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
查看 General Purpose Bit Flag 在 local 和 central headers 中的值。一个明显的迹象是即使对于 core entries 也设置了 bit 0（Encryption）：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
启发式：如果 APK 可以安装并在设备上运行，但工具显示核心条目看起来被“加密”，则 GPBF 已被篡改。

通过在本地文件头 (LFH) 和中央目录 (CD) 条目中清除 GPBF 的第 0 位来修复。最小字节修补器：

<details>
<summary>最小 GPBF 位清除修补器</summary>
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
你现在应该会在核心条目看到 `General Purpose Flag  0000`，工具将能再次解析 APK。

### 2) 大型/自定义 Extra fields 用于破坏解析器

攻击者会在头部填入超大的 Extra fields 和奇怪的 ID 来触发反编译器错误。在真实样本中，你可能会看到嵌入的自定义标记（例如像 `JADXBLOCK` 这样的字符串）。

检查：
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
观察到的示例：未知 ID，比如 `0xCAFE`（"Java Executable"）或 `0x414A`（"JA:"），携带大量载荷。

DFIR heuristics:
- 当核心条目的 Extra 字段异常大时（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`），触发告警。
- 将这些条目上的未知 Extra ID 视为可疑。

Practical mitigation: rebuilding the archive (e.g., re-zipping extracted files) strips malicious Extra fields. If tools refuse to extract due to fake encryption, first clear GPBF bit 0 as above, then repackage:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 文件/目录名称冲突（隐藏真实工件）

一个 ZIP 可以同时包含文件 `X` 和目录 `X/`。一些解压程序和反编译器会混淆，可能会用目录条目覆盖或隐藏真实文件。已经观察到条目与像 `classes.dex` 这样的核心 APK 名称发生冲突。

Triage and safe extraction:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
程序化检测后缀:
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
- 标记本地头标记为加密的 APK（GPBF bit 0 = 1），但仍能被安装/运行的样本。
- 标记核心条目上大型/未知的 Extra fields（查找像 `JADXBLOCK` 这样的标记）。
- 针对 `AndroidManifest.xml`、`resources.arsc`、`classes*.dex` 等，标记路径碰撞（`X` 和 `X/`）。

---

## 其他恶意 ZIP 技巧（2024–2026）

### Concatenated central directories (multi-EOCD evasion)

近期的钓鱼活动会投递单个 blob，实际上是由 **两个 ZIP 文件拼接** 而成。每个都有自己的 End of Central Directory (EOCD) + central directory。不同的解包工具解析不同的目录（7zip 读第一个，WinRAR 读最后一个），让攻击者隐藏只有部分工具能看到的载荷。这也可以绕过仅检查第一个目录的基础 mail gateway AV。

**初步分析命令**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
如果出现多个 EOCD 或出现 "data after payload" 警告，拆分 blob 并检查每个部分：
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

现代的 "better zip bomb" 构建了一个微小的 **kernel**（高度压缩的 DEFLATE 块），并通过重叠的本地头复用它。每个中央目录条目都指向相同的压缩数据，从而在不嵌套归档的情况下达到超过 28M:1 的压缩比。信任中央目录大小的库（Python `zipfile`、Java `java.util.zip`、在强化之前的 Info-ZIP）可能会被迫分配拍字节级别的内存。

**快速检测（重复的 LFH 偏移）**
```python
# detect overlapping entries by identical relative offsets
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
- 进行一次干运行检查：`zipdetails -v file.zip | grep -n "Rel Off"`，并确保偏移量严格递增且唯一。
- 在解压前限制可接受的总未压缩大小和条目数（`zipdetails -t` 或自定义解析器）。
- 必须解压时，在有 CPU 和磁盘限制的 cgroup/VM 中进行（避免无限制膨胀导致崩溃）。

---

### 本地头 (Local-header) vs 中央目录 (central-directory) 解析器混淆

最近的差分解析器研究表明，ZIP 的歧义在现代工具链中仍可被利用。主要思想很简单：有些软件信任 **Local File Header (LFH)**，而有些软件信任 **Central Directory (CD)**，因此同一个归档可以向不同工具呈现不同的文件名、路径、注释、偏移量或条目集合。

实用的攻击用途：
- 使上传过滤器、AV 预扫描或包验证器在 CD 中看到一个无害文件，而 extractor 则遵循不同的 LFH 名称/路径。
- 滥用重复名称、仅存在于某一结构中的条目，或模糊的 Unicode 路径元数据（例如 Info-ZIP Unicode Path Extra Field `0x7075`），使不同解析器重建出不同的树结构。
- 将此与 path traversal 结合，在解压时将“无害”的归档视图变成一个 write-primitive。有关解压侧的内容，请参见 [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)。

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
请提供要补充/翻译的原始 markdown 内容（例如 src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md 的内容）或你想“Complement it with”的具体文本。收到后我会按要求将相关英文翻译为中文，并严格保留原有的 Markdown/HTML 语法与未翻译项。
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
启发式规则：
- 对于 LFH/CD 名称不匹配、重复文件名、多个 EOCD 记录，或在最后一个 EOCD 之后有多余字节的归档，应拒绝或隔离。
- 如果不同工具对解压后的树结构存在分歧，则对于使用不寻常的 Unicode-path extra fields 或注释不一致的 ZIPs，应视为可疑。
- 如果分析比保留原始字节更重要，应在 sandbox 中提取后使用严格的 parser 对归档重新打包，并将生成的文件列表与原始元数据进行比较。

这不仅在 package ecosystems 中重要：相同类别的歧义可以将 payload 隐藏在 mail gateways、static scanners 和在另一个 extractor 处理归档之前会 “peek” ZIP 内容的自定义 ingestion pipelines 之中。

---



## 参考资料

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
