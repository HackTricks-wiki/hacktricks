# ZIPs 技巧

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** for managing **zip files** are essential for diagnosing, repairing, and cracking zip files. Here are some key utilities:

- **`unzip`**：揭示为什么 zip files 可能无法解压。
- **`zipdetails -v`**：提供对 zip file format 字段的详细分析。
- **`zipinfo`**：列出 zip files 的内容而不提取它们。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的 zip files。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：用于暴力破解 zip 密码的工具，对大约 7 个字符以内的密码有效。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) 提供了关于 zip files 结构和标准的全面细节。

需要注意的是，受密码保护的 zip files **并不加密文件名或文件大小**，这是一个安全缺陷，RAR 或 7z 并不具有这种问题。此外，使用旧的 ZipCrypto 方法加密的 zip files 在存在未加密的已压缩文件副本时易受 **plaintext attack**，该攻击利用已知内容来破解 zip 的密码。关于此漏洞的细节可见 [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) 以及 [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)。然而，使用 **AES-256** 加密的 zip files 对此 plaintext attack 免疫，这凸显了为敏感数据选择安全加密方法的重要性。

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Modern Android malware droppers use malformed ZIP metadata to break static tools (jadx/apktool/unzip) while keeping the APK installable on-device. The most common tricks are:

- 伪造加密：通过设置 ZIP General Purpose Bit Flag (GPBF) 的 bit 0 来 Fake encryption
- 滥用大型/自定义的 Extra fields 来混淆解析器
- 文件/目录名称冲突以隐藏真实痕迹（例如，在真实的 `classes.dex` 旁边存在名为 `classes.dex/` 的目录）

### 1) Fake encryption (GPBF bit 0 set) without real crypto

症状：
- `jadx-gui` 失败并出现类似错误：

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` 会提示核心 APK 文件需要密码，尽管有效的 APK 不能对 `classes*.dex`、`resources.arsc` 或 `AndroidManifest.xml` 进行加密：

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
查看本地和中央头部的 General Purpose Bit Flag。一个明显的迹象是第 0 位被设置（Encryption），即使是针对核心条目也会这样：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
启发式：如果 APK 在设备上安装并运行，但工具把核心条目显示为 "encrypted"，则 GPBF 已被篡改。

修复方法：在 Local File Headers (LFH) 和 Central Directory (CD) 条目中将 GPBF 的第 0 位清零。最小字节补丁器：

<details>
<summary>最小 GPBF 位清除补丁器</summary>
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
你现在应该在核心条目上看到 `General Purpose Flag  0000`，工具将再次解析 APK。

### 2) 大型/自定义 Extra fields 用于破坏解析器

攻击者会在头部填入超大的 Extra fields 和奇怪的 ID 来绊倒反编译器。在实战中，你可能会看到嵌入的自定义标记（例如像 `JADXBLOCK` 这样的字符串）。

检查：
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
观察到的示例：未知 ID 例如 `0xCAFE`（"Java 可执行文件"）或 `0x414A`（"JA:"）携带大量载荷。

DFIR heuristics:
- 当核心条目的 Extra 字段异常大时触发告警（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）。
- 将这些条目上的未知 Extra ID 视为可疑。

Practical mitigation: 重建归档（例如，重新压缩已提取的文件）会去除恶意的 Extra 字段。如果工具因伪加密而拒绝解压，先如上清除 GPBF bit 0，然后重新打包：
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 文件/目录名称冲突（隐藏真实工件）

一个 ZIP 可以同时包含文件 `X` 和目录 `X/`。某些解压工具和反编译器会混淆，可能会用目录条目覆盖或隐藏真实的文件。已经观察到条目与核心 APK 名称（例如 `classes.dex`）冲突的情况。

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
Blue-team 检测建议：
- 标记那些本地头部标记为加密（GPBF bit 0 = 1）但仍能安装/运行的 APK。
- 标记核心条目上大小异常或未知的 Extra 字段（寻找类似 `JADXBLOCK` 的标记）。
- 标记路径冲突（`X` 和 `X/`），尤其针对 `AndroidManifest.xml`、`resources.arsc`、`classes*.dex`。

---

## 其他恶意 ZIP 技巧（2024–2025）

### 串联的中央目录（multi-EOCD 绕过）

最近的钓鱼活动会发送一个单一 blob，实际上是由 **两个 ZIP 文件串联** 而成。每个都有自己的 End of Central Directory (EOCD) + central directory。不同的解压程序会解析不同的目录（7zip 读取第一个，WinRAR 读取最后一个），这允许攻击者隐藏仅部分工具可见的负载。这也能绕过仅检查第一个目录的基础邮件网关 AV。

**初步分析命令**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
如果出现多个 EOCD 或出现 "data after payload" 警告，请将 blob 拆分并检查每个部分：
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

现代的 "better zip bomb" 构建了一个极小的 **kernel**（高度压缩的 DEFLATE block），并通过重叠的 local headers 重用它。每个 central directory entry 都指向相同的压缩数据，在不嵌套归档的情况下实现超过 28M:1 的比率。信任 central directory 大小的库（Python `zipfile`、Java `java.util.zip`、Info-ZIP 在未强化的构建之前）可能被迫分配 petabytes。

**快速检测（重复 LFH 偏移）**
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
- 执行干运行检查： `zipdetails -v file.zip | grep -n "Rel Off"` 并确保偏移量严格递增且唯一。
- 在解压前限制可接受的总未压缩大小和条目数量（`zipdetails -t` 或自定义解析器）。
- 如果必须解压，请在带有 CPU 与磁盘限制的 cgroup/VM 中进行（避免无限膨胀导致崩溃）。

---

## 参考资料

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
