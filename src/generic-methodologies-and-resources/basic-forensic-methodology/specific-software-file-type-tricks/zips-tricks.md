# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** for managing **zip files** are essential for diagnosing, repairing, and cracking zip files. Here are some key utilities:

- **`unzip`**：显示 zip 文件无法解压的原因。
- **`zipdetails -v`**：提供对 zip 文件格式字段的详细分析。
- **`zipinfo`**：列出 zip 文件的内容而不进行解压。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的 zip 文件。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：用于对 zip 密码进行暴力破解的工具，对于大约 7 个字符以内的密码效果较好。

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

It's crucial to note that password-protected zip files **do not encrypt filenames or file sizes** within, a security flaw not shared with RAR or 7z files which encrypt this information. Furthermore, zip files encrypted with the older ZipCrypto method are vulnerable to a **plaintext attack** if an unencrypted copy of a compressed file is available. This attack leverages the known content to crack the zip's password, a vulnerability detailed in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) and further explained in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). However, zip files secured with **AES-256** encryption are immune to this plaintext attack, showcasing the importance of choosing secure encryption methods for sensitive data.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Modern Android malware droppers use malformed ZIP metadata to break static tools (jadx/apktool/unzip) while keeping the APK installable on-device. The most common tricks are:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Symptoms:
- `jadx-gui` fails with errors like:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` prompts for a password for core APK files even though a valid APK cannot have encrypted `classes*.dex`, `resources.arsc`, or `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detection with zipdetails:
```bash
zipdetails -v sample.apk | less
```
查看本地和中央标头的 General Purpose Bit Flag。一个明显的指标是即使针对核心条目也设置了 bit 0（Encryption）：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
启发式：如果 APK 能在设备上安装并运行，但核心条目对工具显示为“加密”，说明 GPBF 已被篡改。

修复方法：在 Local File Headers (LFH) 和 Central Directory (CD) 条目中清除 GPBF 的位 0。最小字节修补器：

<details>
<summary>最小 GPBF 位清除补丁</summary>
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
现在你应该能在核心条目上看到 `General Purpose Flag  0000`，工具将重新解析 APK。

### 2) 大型/自定义 额外字段以破坏解析器

攻击者会在头部填充超大的额外字段和奇怪的 ID 来干扰反编译器。在实际环境中，你可能会看到嵌入的自定义标记（例如像 `JADXBLOCK` 这样的字符串）。

检查：
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
观察到的示例：未知 ID（如 `0xCAFE`（"Java 可执行文件"）或 `0x414A`（"JA:"））携带大量负载。

DFIR 启发式规则：
- 在核心条目（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）的 Extra 字段异常大时发出告警。
- 将这些条目上的未知 Extra ID 视为可疑。

实际缓解措施：重建归档（例如，重新压缩已提取的文件）会去除恶意的 Extra 字段。如果工具因伪造的加密而拒绝提取，先按上文清除 GPBF bit 0，然后重新打包：
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 文件/目录 名称冲突（隐藏真实的工件）

一个 ZIP 可以同时包含文件 `X` 和目录 `X/`。一些解压器和反编译器会混淆，可能会用目录条目覆盖或隐藏真实的文件。已观察到条目与核心 APK 名称（例如 `classes.dex`）冲突时出现这种情况。

初步分析与安全提取：
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
程序化检测后缀：
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
Blue-team detection ideas:
- 标记本地头部标记为加密 (GPBF bit 0 = 1) 但仍能安装/运行的 APK。
- 标记核心条目上较大或未知的 Extra 字段（查找类似 `JADXBLOCK` 的标记）。
- 标记路径冲突（`X` 和 `X/`），尤其针对 `AndroidManifest.xml`、`resources.arsc`、`classes*.dex`。

---

## Other malicious ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

近期的钓鱼活动常发送一个 blob，实际上是 **两个 ZIP 文件串联**。每个都有自己的 End of Central Directory (EOCD) + central directory。不同的解压工具会解析不同的目录（7zip 读取第一个，WinRAR 读取最后一个），这让攻击者能够隐藏只有部分工具能看到的 payloads。此方法也能绕过只检查第一个目录的基本 mail gateway AV。

**排查命令**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
如果出现多个 EOCD 或有 "data after payload" 警告，请将 blob 拆分并检查每个部分：
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" 构造了一个微小的 **kernel**（高度压缩的 DEFLATE 块），并通过重叠的 local headers 重用它。每个 central directory entry 都指向相同的压缩数据，在不嵌套归档的情况下可实现超过 >28M:1 的比率。那些信任 central directory 大小的库（Python `zipfile`、Java `java.util.zip`、Info-ZIP 在加固之前）可能会被迫分配 petabytes 级别的空间。

**快速检测 (duplicate LFH offsets)**
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
- Perform a dry-run walk: `zipdetails -v file.zip | grep -n "Rel Off"` and ensure offsets are strictly increasing and unique.
- 在解压之前限制接受的总未压缩大小和条目数量（`zipdetails -t` 或自定义解析器）。
- When you must extract, do it inside a cgroup/VM with CPU+disk limits (avoid unbounded inflation crashes).

---

### Local-header vs central-directory 解析器混淆

最近的差异解析器研究表明，ZIP 的歧义在现代工具链中仍然可被利用。主要思想很简单：一些软件信任 **Local File Header (LFH)**，而另一些则信任 **Central Directory (CD)**，因此同一个归档可以向不同工具呈现不同的文件名、路径、注释、偏移量或条目集合。

Practical offensive uses:
- 使上传过滤器、AV 预扫描或包验证器在 CD 中看到一个良性文件，而解压器遵从不同的 LFH 名称/路径。
- 滥用重复名称、仅存在于某一结构的条目，或模糊的 Unicode 路径元数据（例如 Info-ZIP Unicode Path Extra Field `0x7075`），以致不同解析器重建出不同的树。
- 将此与 path traversal 结合，在解压过程中将“无害”的归档视图转变为 write-primitive。有关解压方面的内容，请参见 [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)。

DFIR triage:
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
请提供要补充的内容或文件 src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md 的文本，我会将相关英文翻译为中文并保持原有的 Markdown/HTML 语法不变。
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
启发式判断:
- 拒绝或隔离那些具有不匹配的 LFH/CD 名称、重复的文件名、多重 EOCD 记录，或在最终 EOCD 之后存在尾随字节的归档文件。
- 如果不同工具对提取出的目录树存在分歧，则将使用不寻常的 Unicode-path extra fields 或注释不一致的 ZIPs 视为可疑。
- 如果分析比保留原始字节更重要，则在 sandbox 中提取后使用严格的 parser 重新打包归档文件，并将生成的文件列表与原始元数据进行比较。

这不仅在 package ecosystems 中重要：同一类歧义可以将有效载荷隐藏在 mail gateways、static scanners 和在不同 extractor 处理归档之前会“peek” ZIP 内容的自定义 ingestion pipelines 之中。

---



## 参考

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
