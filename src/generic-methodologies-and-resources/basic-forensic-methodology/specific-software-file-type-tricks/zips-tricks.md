# ZIPs 技巧

{{#include ../../../banners/hacktricks-training.md}}

用于管理 **zip files** 的 **命令行工具** 对诊断、修复和破解 zip files 至关重要。以下是一些关键工具：<sup>[[1]](#references)</sup>

- **`unzip`**：揭示 zip file 可能无法解压的原因。
- **`zipdetails -v`**：提供 zip file 格式字段的详细分析。
- **`zipinfo`**：列出 zip file 的内容而不进行提取。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的 zip files。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：用于暴力破解 zip passwords 的工具，对长度约 7 个字符以内的 passwords 有效。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) 提供了有关 zip files 结构和标准的全面细节。<sup>[[4]](#references)</sup>

需要特别注意的是，受 password 保护的 zip files **不会加密其中的 filenames 或 file sizes**，这是一个 RAR 或 7z files 不存在的安全缺陷，因为后两者会加密这些信息。此外，如果存在某个 compressed file 的未加密副本，使用较旧的 ZipCrypto 方法加密的 zip files 容易受到 **plaintext attack** 攻击。<sup>[[1]](#references)</sup> 该攻击利用已知内容破解 zip 的 password，[HackThis 的文章](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)详细介绍了这一漏洞，[这篇学术论文](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)也对此进行了进一步解释。<sup>[[11]](#references)[[12]](#references)</sup> 然而，使用 **AES-256** encryption 保护的 zip files 不受此 plaintext attack 影响，说明为敏感数据选择安全 encryption methods 的重要性。<sup>[[1]](#references)</sup>

---

## 使用经过操纵的 ZIP headers 对 APKs 进行 Anti-reversing tricks

现代 Android malware droppers 会使用 malformed ZIP metadata 破坏 static tools（jadx/apktool/unzip）的工作，同时确保 APK 仍可在设备上安装。最常见的 tricks 包括：<sup>[[2]](#references)</sup>

- 通过设置 ZIP General Purpose Bit Flag（GPBF）的 bit 0 来伪造 encryption
- 滥用大型或自定义 Extra fields 来混淆 parsers
- File/directory name collisions，用于隐藏真实 artifacts（例如，在真实的 `classes.dex` 旁放置一个名为 `classes.dex/` 的 directory）

### 1) Fake encryption（设置 GPBF bit 0）但不使用真正的 crypto

症状：
- `jadx-gui` 失败并显示类似以下错误：

```text
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- 即使有效的 APK 不可能对 `classes*.dex`、`resources.arsc` 或 `AndroidManifest.xml` 进行 encryption，`unzip` 仍会为核心 APK files 请求 password：

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
查看本地和中央标头中的 General Purpose Bit Flag。一个明显的值是：即使对于核心条目，bit 0 也被设置（Encryption）：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristic：如果 APK 能在设备上安装并运行，但工具显示核心条目似乎是“encrypted”，则说明 GPBF 被篡改了。

通过清除 Local File Headers (LFH) 和 Central Directory (CD) 条目中的 GPBF bit 0 来修复。最小化的 byte-patcher：

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
现在你应该会在核心条目中看到 `General Purpose Flag  0000`，工具也将能够再次解析 APK。

### 2) 用大型/自定义 Extra 字段破坏解析器

攻击者会在 headers 中填充超大的 Extra 字段和异常 ID，以干扰反编译器。在实际环境中，你可能会看到其中嵌入了自定义标记（例如类似 `JADXBLOCK` 的字符串）。

检查：
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
观察到的示例：携带大型 payload 的未知 ID，例如 `0xCAFE`（"Java Executable"）或 `0x414A`（"JA:"）。

DFIR 启发式规则：
- 当核心条目（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）中的 Extra fields 异常大时发出警报。
- 将这些条目上的未知 Extra IDs 视为可疑。

实用缓解措施：重新构建 archive（例如，将提取出的文件重新压缩）会移除恶意 Extra fields。如果工具因伪造的 encryption 而拒绝提取，先按上文所述清除 GPBF bit 0，然后重新打包：
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 文件/目录名称冲突（隐藏真实 artifacts）

ZIP 可以同时包含文件 `X` 和目录 `X/`。某些解压工具和反编译器会因此混淆，可能使用目录条目覆盖或隐藏真实文件。已发现条目会与 `classes.dex` 等核心 APK 名称发生冲突。

分流和安全解压：
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
Blue-team detection ideas:
- 标记本地 headers 将加密标记为开启（GPBF bit 0 = 1）但仍能安装/运行的 APK。
- 标记核心 entries 上较大或未知的 Extra fields（查找类似 `JADXBLOCK` 的 markers）。
- 专门针对 `AndroidManifest.xml`、`resources.arsc`、`classes*.dex`，标记路径冲突（`X` 和 `X/`）。

---

## Other malicious ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

近期的 phishing campaigns 会发送一个实际上是**两个 ZIP files 拼接而成的单一 blob**。每个文件都有自己的 End of Central Directory (EOCD) 和 central directory。不同的 extractors 会解析不同的 directories（7zip 读取第一个，WinRAR 读取最后一个），从而让 attackers 隐藏只有某些 tools 才能显示的 payloads。这也能绕过只检查第一个 directory 的基础 mail gateway AV。<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
如果出现多个 EOCD，或出现“data after payload”警告，请拆分 blob 并检查每个部分：
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

现代的“better zip bomb”会构建一个微型 **kernel**（高度压缩的 DEFLATE block），并通过重叠的 local headers 重复利用它。每个 central directory entry 都指向相同的 compressed data，在不嵌套 archives 的情况下实现超过 28M:1 的压缩比。信任 central directory 大小的库（Python `zipfile`、Java `java.util.zip`、加固版本之前的 Info-ZIP）可能被迫分配数 PB 的内存。<sup>[[7]](#references)[[8]](#references)</sup>

**快速检测（重复的 LFH offsets）**
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
- Perform a dry-run walk: `zipdetails -v file.zip | grep -n "Rel Off"`，并确保 offsets 严格递增且唯一。
- 在 extraction 前限制允许的 total uncompressed size 和 entry count（`zipdetails -t` 或 custom parser）。
- 必须 extraction 时，在具有 CPU+disk limits 的 cgroup/VM 内执行（避免无界 inflation crashes）。

---

### Local-header vs central-directory parser confusion

Recent differential-parser research 表明，ZIP ambiguity 在 modern toolchains 中仍可被 exploit。核心思路很简单：某些 software 信任 **Local File Header (LFH)**，而其他 software 信任 **Central Directory (CD)**，因此同一个 archive 可以向不同 tools 展示不同的 filenames、paths、comments、offsets 或 entry sets。<sup>[[9]](#references)</sup>

Practical offensive uses:
- 让 upload filter、AV pre-scan 或 package validator 在 CD 中看到 benign file，而 extractor 遵循不同的 LFH name/path。
- 利用 duplicate names、仅存在于某一个 structure 中的 entries，或 ambiguous Unicode path metadata（例如 Info-ZIP Unicode Path Extra Field `0x7075`），使不同 parsers 重建出不同的 trees。
- 将其与 path traversal 结合，把“harmless”的 archive view 转变为 extraction 期间的 write-primitive。关于 extraction side，请参阅 [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)。

DFIR triage：
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
补充以下内容：
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
启发式规则：
- 拒绝或隔离 LFH/CD 名称不匹配、包含重复文件名、多个 EOCD 记录，或最终 EOCD 后存在尾随字节的归档文件。<sup>[[10]](#references)</sup>
- 如果不同工具对提取出的文件树给出不同结果，则应将使用异常 Unicode 路径 extra fields 或不一致注释的 ZIP 视为可疑。<sup>[[9]](#references)</sup>
- 如果分析比保留原始字节更重要，请在 sandbox 中提取归档文件后，使用严格的 parser 重新打包，并将生成的文件列表与原始 metadata 进行比较。

这不仅适用于 package ecosystems：同类歧义也可以从 mail gateways、static scanners 和 custom ingestion pipelines 中隐藏 payload，因为这些组件可能会在由其他 extractor 处理归档文件之前先“窥探”ZIP 内容。

---



## References

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: Cracking ZIP Files](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
