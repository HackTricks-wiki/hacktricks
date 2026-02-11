# ZIPs 技巧

{{#include ../../../banners/hacktricks-training.md}}

**命令行工具** 用于管理 **zip files** 对于诊断、修复和破解 zip 文件至关重要。以下是一些关键工具：

- **`unzip`**：显示 zip 文件无法解压的原因。
- **`zipdetails -v`**：提供对 zip 文件格式字段的详细分析。
- **`zipinfo`**：在不解压的情况下列出 zip 文件的内容。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的 zip 文件。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：用于对 zip 密码进行暴力破解的工具，对大约 7 字符以内的密码效果良好。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) 提供了有关 zip 文件结构和标准的全面细节。

需要注意的是，受密码保护的 zip files 并不加密内部的文件名或文件大小，这是一个安全缺陷；RAR 或 7z 文件会加密这些信息，zip 则不然。此外，使用较旧的 ZipCrypto 方法加密的 zip files 如果存在未加密的压缩文件副本，则容易受到 plaintext attack。此攻击利用已知内容来破解 zip 的密码，该漏洞在 [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) 中有详细说明，并在 [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) 中进一步解释。然而，使用 **AES-256** 加密的 zip files 对该 plaintext attack 免疫，突显了为敏感数据选择安全加密方法的重要性。

---

## 在 APK 中利用被篡改的 ZIP headers 的反逆向技巧

现代 Android malware droppers 使用格式错误的 ZIP 元数据来破坏静态工具 (jadx/apktool/unzip)，同时保持 APK 在设备上可安装。最常见的技巧有：

- 通过设置 ZIP General Purpose Bit Flag (GPBF) 的 bit 0 来伪造加密
- 滥用大型/自定义的 Extra fields 来混淆解析器
- 文件/目录名冲突以隐藏真实痕迹（例如，在真实的 `classes.dex` 旁边有一个名为 `classes.dex/` 的目录）

### 1) Fake encryption (GPBF bit 0 set) without real crypto

症状：
- `jadx-gui` 出现类似错误：

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` 会提示 core APK 文件的密码，尽管有效的 APK 不可能对 `classes*.dex`、`resources.arsc` 或 `AndroidManifest.xml` 进行加密：

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

使用 zipdetails 的检测：
```bash
zipdetails -v sample.apk | less
```
查看本地和中央头部的通用用途位标志（General Purpose Bit Flag）。一个明显的特征是即使对于核心条目，bit 0 也被设置（加密）：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
启发式：如果 APK 在设备上安装并运行，但核心条目对工具看起来“加密”，则 GPBF 已被篡改。

修复方法是在 Local File Headers (LFH) 和 Central Directory (CD) 条目中清除 GPBF 的第 0 位。最小字节修补器：

<details>
<summary>最小 GPBF 位清除字节修补器</summary>
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

使用:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
现在你应该在核心条目上看到 `General Purpose Flag  0000`，工具会再次解析 APK。

### 2) 大型/自定义 Extra 字段以破坏解析器

攻击者会在头部填入超大的 Extra 字段和奇怪的 ID 来诱使反编译器出错。在实际环境中，你可能会看到嵌入的自定义标记（例如像 `JADXBLOCK` 这样的字符串）。

检查：
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
观察到的示例：未知 ID（例如 `0xCAFE` ("Java Executable") 或 `0x414A` ("JA:")）携带了较大的 payload。

DFIR heuristics:
- 当核心条目的 Extra fields 异常大时（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`），发出警报。
- 将这些条目上的未知 Extra ID 视为可疑。

Practical mitigation: rebuilding the archive (e.g., re-zipping extracted files) 会剥除恶意的 Extra fields。如果工具因假加密而拒绝解压，先按上文那样清除 GPBF bit 0，然后重新打包：
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 文件/目录 名称冲突（隐藏真实工件）

一个 ZIP 可以同时包含一个文件 `X` 和一个目录 `X/`。一些解压程序和反编译器会混淆，可能会用目录条目覆盖或隐藏真实文件。这种情况已在与核心 APK 名称（如 `classes.dex`）冲突的条目中被观察到。

初步分类与安全提取：
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
用于程序化检测的后缀:
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
Blue-team 检测思路:
- Flag APKs whose local headers mark encryption (GPBF bit 0 = 1) yet install/run.
- Flag large/unknown Extra fields on core entries (look for markers like `JADXBLOCK`).
- Flag path-collisions (`X` and `X/`) specifically for `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## 其他恶意 ZIP 技巧（2024–2025）

### 串联的中央目录 (multi-EOCD evasion)

最近的 phishing 活动会分发一个实际上由 **两个 ZIP 文件串联** 而成的 blob。每个都有自己的 End of Central Directory (EOCD) + central directory。不同的解压器会解析不同的目录（7zip 读取第一个，WinRAR 读取最后一个），使攻击者能够隐藏只有部分工具能看到的 payloads。这也能绕过只检查第一个目录的基础 mail gateway AV。

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
如果出现多个 EOCD 或出现 "data after payload" 警告，则将 blob 拆分并检查每一部分：
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

现代的 "better zip bomb" 构造了一个微小的 **kernel**（高度压缩的 DEFLATE 块），并通过重叠的 local headers 重复使用它。每个中央目录条目都指向相同的压缩数据，从而在无需嵌套归档的情况下实现超过 28M:1 的比率。信任中央目录大小的库（Python `zipfile`、Java `java.util.zip`、Info-ZIP 在加固之前的版本）可能会被迫分配到 petabytes（PB）级别的空间。

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
- 先进行干运行遍历：`zipdetails -v file.zip | grep -n "Rel Off"` 并确保偏移量严格递增且唯一。
- 在解压前限制接受的总未压缩大小和条目数量（`zipdetails -t` 或自定义解析器）。
- 如果必须解压，请在带有 CPU+disk 限制的 cgroup/VM 中进行（以避免无限膨胀导致的崩溃）。

---

## 参考资料

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
