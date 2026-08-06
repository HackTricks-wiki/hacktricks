# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

用于管理 **zip files** 的**命令行工具**对于诊断、修复和破解 zip files 至关重要。以下是一些关键工具：<sup>[[1]](#references)</sup>

- **`unzip`**：揭示 zip file 可能无法解压的原因。
- **`zipdetails -v`**：对 zip file 格式字段进行详细分析。<sup>[[3]](#references)</sup>
- **`zipinfo`**：列出 zip file 的内容，而不提取文件。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的 zip files。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：用于 brute-force cracking zip passwords 的工具，对长度约 7 个字符以内的密码较为有效。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) 提供了有关 zip files 结构和标准的全面细节。<sup>[[4]](#references)</sup>

需要注意的是，受密码保护的 zip files **不会加密其中的文件名或文件大小**，这是一个安全缺陷；RAR 或 7z files 会加密这些信息，因此不存在该缺陷。此外，如果有某个 compressed file 的未加密副本，使用旧版 ZipCrypto 方法加密的 zip files 容易受到 **plaintext attack** 攻击。<sup>[[1]](#references)</sup> 该攻击利用已知内容破解 zip 的密码，具体漏洞详见 [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)，并在[这篇 academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)中进一步说明。<sup>[[11]](#references)[[12]](#references)</sup> 但是，使用 **AES-256** encryption 保护的 zip files 不受此 plaintext attack 影响，体现了为敏感数据选择安全 encryption methods 的重要性。<sup>[[1]](#references)</sup>

---

## 使用 manipulated ZIP headers 对 APKs 进行 anti-reversing tricks

现代 Android malware droppers 使用 malformed ZIP metadata 来破坏 static tools（jadx/apktool/unzip）的工作，同时保持 APK 在设备上可安装。最常见的 tricks 包括：<sup>[[2]](#references)</sup>

- 通过设置 ZIP General Purpose Bit Flag（GPBF）的 bit 0 来伪造 encryption
- 滥用大型或自定义 Extra fields 混淆 parsers
- 文件名和目录名冲突，以隐藏真实 artifacts（例如，在真正的 `classes.dex` 旁边放置名为 `classes.dex/` 的目录）

### 1) 伪造 encryption（设置 GPBF bit 0），但不使用真正的 crypto

现象：
- `jadx-gui` 失败并显示类似以下错误：

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` 会要求输入核心 APK files 的密码，尽管有效的 APK 不可能加密 `classes*.dex`、`resources.arsc` 或 `AndroidManifest.xml`：

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
查看本地标头和中央标头中的通用用途位标志。一个明显的值是即使对于核心条目，位 0 也被设置为（Encryption）：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
启发式判断：如果 APK 能在设备上安装并运行，但其核心条目在工具中显示为“加密”，则说明 GPBF 已被篡改。

修复方法是清除 Local File Headers (LFH) 和 Central Directory (CD) 条目中的 GPBF 第 0 位。最小化字节修补器：

<details>
<summary>最小化 GPBF 位清除修补器</summary>
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
你现在应该会在核心条目中看到 `General Purpose Flag  0000`，工具也将能够再次解析 APK。

### 2) 使用大型/自定义 Extra fields 破坏解析器

攻击者会在 headers 中填充超大的 Extra fields 和异常 ID，以干扰反编译器。在实际环境中，你可能会看到其中嵌入的自定义标记（例如类似 `JADXBLOCK` 的字符串）。

检查：
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
观察到的示例：携带大型 payload 的未知 ID，例如 `0xCAFE`（“Java Executable”）或 `0x414A`（“JA:”）。

DFIR 启发式规则：
- 当核心条目（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）中的 Extra fields 异常大时发出警报。
- 将这些条目上的未知 Extra ID 视为可疑。

实际缓解措施：重建 archive（例如重新压缩提取出的文件）会清除恶意 Extra fields。如果工具因伪造的 encryption 而拒绝提取，先按上文所述清除 GPBF bit 0，然后重新打包：
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 文件/目录名称冲突（隐藏真实 artifacts）

ZIP 可以同时包含文件 `X` 和目录 `X/`。某些提取器和反编译器会因此混淆，可能使用目录条目覆盖或隐藏真实文件。已观察到与 `classes.dex` 等核心 APK 名称发生冲突的条目。

分流与安全提取：
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
- 标记本地 headers 将 encryption 标记为启用（GPBF bit 0 = 1）但仍能安装/运行的 APK。
- 标记核心 entries 上较大或未知的 Extra fields（查找类似 `JADXBLOCK` 的 markers）。
- 专门针对 `AndroidManifest.xml`、`resources.arsc`、`classes*.dex` 标记路径冲突（`X` 和 `X/`）。

---

## Other malicious ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

近期的 phishing campaigns 会发布一个实际上由**两个串联的 ZIP 文件**组成的单一 blob。每个文件都有自己的 End of Central Directory (EOCD) + central directory。不同的 extractors 会解析不同的 directories（7zip 读取第一个，WinRAR 读取最后一个），从而让 attackers 隐藏只有部分 tools 能显示的 payloads。这也能绕过只检查第一个 directory 的基础 mail gateway AV。<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
如果出现多个 EOCD，或有“data after payload”警告，请拆分 blob 并检查每一部分：
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs（non-recursive）

现代的“better zip bomb”构建一个极小的 **kernel**（高度压缩的 DEFLATE block），并通过重叠的 local headers 重复使用它。每个 central directory entry 都指向相同的压缩数据，在不嵌套 archives 的情况下实现超过 28M:1 的压缩比。信任 central directory 大小的 Libraries（Python `zipfile`、Java `java.util.zip`、加固版本之前的 Info-ZIP）可能被迫分配数 PB 的内存。<sup>[[7]](#references)[[8]](#references)</sup>

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
- 执行 dry-run 遍历：`zipdetails -v file.zip | grep -n "Rel Off"`，并确保 offsets 严格递增且唯一。
- 在 extraction 前限制允许的总 uncompressed size 和 entry 数量（使用 `zipdetails -t` 或自定义 parser）。
- 必须 extraction 时，在带有 CPU 和 disk limits 的 cgroup/VM 内执行（避免无界 inflation 导致崩溃）。

---

### Local-header 与 central-directory parser 混淆

近期的 differential-parser research 表明，ZIP ambiguity 在现代 toolchain 中仍然可被利用。核心思路很简单：某些 software 信任 **Local File Header (LFH)**，而另一些信任 **Central Directory (CD)**，因此同一个 archive 可以向不同 tools 呈现不同的 filenames、paths、comments、offsets 或 entry sets。<sup>[[9]](#references)</sup>

实际 offensive uses：
- 让 upload filter、AV pre-scan 或 package validator 在 CD 中看到 benign file，而 extractor 则遵循不同的 LFH name/path。
- 利用 duplicate names、仅存在于某一个 structure 中的 entries，或存在歧义的 Unicode path metadata（例如 Info-ZIP Unicode Path Extra Field `0x7075`），使不同 parsers 重建出不同的 trees。
- 将其与 path traversal 结合，把“harmless”的 archive view 转化为 extraction 期间的 write-primitive。关于 extraction 侧，请参阅 [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)。

DFIR 初步筛查：
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
使用以下内容补充：
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
启发式规则：
- 拒绝或隔离 LFH/CD 名称不匹配、文件名重复、包含多个 EOCD 记录，或最终 EOCD 后存在尾随字节的 archive。<sup>[[10]](#references)</sup>
- 如果不同工具对提取出的文件树产生不一致结果，则应将使用异常 Unicode-path extra fields 或不一致 comments 的 ZIP 视为可疑。<sup>[[9]](#references)</sup>
- 如果分析比保留原始字节更重要，则应在 sandbox 中提取 archive 后，使用严格 parser 重新打包，并将生成的文件列表与原始 metadata 进行比较。

这不仅与 package ecosystems 有关：同一类歧义还可以将 payloads 隐藏起来，绕过 mail gateways、static scanners 以及那些在由不同 extractor 处理 archive 之前先“窥探”ZIP 内容的 custom ingestion pipelines。

---



## 参考资料

- [1] [CTF Forensics Field Guide（Mike's Blog，CTF category）](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper（APK ZIP anti-reversing）](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails（Archive::Zip script）](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [ZIP File Format Specification（PKWARE APPNOTE.TXT）](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected（Perception Point）](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb（David Fifield，USENIX WOOT 2019）](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers（USENIX Security 2025）](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext（Michael Stay，AccessData Corporation）](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: Cracking ZIP Files](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
