# ZIPs 技巧

{{#include ../../../banners/hacktricks-training.md}}

**命令行工具** 用于管理 **zip 文件** 对诊断、修复和破解 zip 文件至关重要。以下是一些关键实用程序：

- **`unzip`**：显示 zip 文件无法解压的原因。
- **`zipdetails -v`**：提供对 zip 文件格式字段的详细分析。
- **`zipinfo`**：列出 zip 文件的内容而不解压它们。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的 zip 文件。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：一个用于对 zip 密码进行暴力破解的工具，对大约 7 个字符左右的密码有效。

该 [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) 提供关于 zip 文件结构和标准的全面细节。

需要注意的是，受密码保护的 zip 文件 **不会对其中的文件名或文件大小进行加密**，这是一个安全缺陷，RAR 或 7z 等格式通过加密这些信息避免了该问题。此外，使用较旧的 ZipCrypto 方法加密的 zip 文件在存在某个压缩文件的未加密副本时容易受到 **plaintext attack**。该攻击利用已知内容来破解 zip 的密码，这一漏洞在 [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) 中有详细说明，并在 [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) 中进一步解释。然而，使用 **AES-256** 加密的 zip 文件对这种 plaintext attack 免疫，凸显为敏感数据选择安全加密方法的重要性。

---

## 在 APK 中使用被操纵的 ZIP 头部的反逆向技巧

现代 Android 恶意软件 dropper 使用畸形的 ZIP 元数据来破坏静态工具（jadx/apktool/unzip），同时保持 APK 可在设备上安装。最常见的技巧包括：

- 通过设置 ZIP General Purpose Bit Flag (GPBF) 的第 0 位来伪造加密
- 滥用大型/自定义 Extra 字段以混淆解析器
- 文件/目录名冲突以隐藏真实痕迹（例如，在真实的 `classes.dex` 旁边有一个名为 `classes.dex/` 的目录）

### 1) 伪造加密（设置 GPBF 第 0 位）但没有真正的加密

症状：
- `jadx-gui` 会出现类似错误：

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` 会针对核心 APK 文件提示输入密码，尽管有效的 APK 不可能对 `classes*.dex`, `resources.arsc`, 或 `AndroidManifest.xml` 进行加密：

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
查看本地文件头和中央目录头的通用用途位标志。一个明显的值是即使对于核心条目也设置了 bit 0（Encryption）：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
启发式：如果一个 APK 能在设备上安装并运行，但在工具中核心条目显示为“加密”，则 GPBF 已被篡改。

通过清除 Local File Headers (LFH) 和 Central Directory (CD) 条目中的 GPBF bit 0 来修复。最小字节补丁程序：
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
用法:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
你现在应该会在核心条目上看到 `General Purpose Flag  0000`，工具将再次解析 APK。

### 2) 大/自定义 Extra fields 来破坏 parsers

攻击者会将超大的 Extra fields 和奇怪的 ID 塞入 headers 以诱发 decompilers。在实战中你可能会看到自定义标记（例如像 `JADXBLOCK` 这样的字符串）嵌入其中。

检查：
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
观察到的示例：未知 ID，例如 `0xCAFE`（"Java Executable"）或 `0x414A`（"JA:"）承载大量 payload。

DFIR heuristics:
- 当核心条目的 Extra fields 异常大时触发告警（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）。
- 将这些条目上的未知 Extra IDs 视为可疑。

实际缓解措施：重建归档（例如，重新压缩已解压的文件）会去除恶意的 Extra 字段。如果工具因伪造的加密而拒绝解压，先如上清除 GPBF bit 0，然后重新打包：
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 文件/目录名称冲突（隐藏真实工件）

ZIP 可以同时包含文件 `X` 和目录 `X/`。某些提取器和反编译器可能会混淆，并可能用目录条目覆盖或隐藏真实文件。已在与核心 APK 名称（如 `classes.dex`）冲突的条目中观察到这种情况。

分类与安全提取：
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
Blue-team 检测思路:
- 标记本地头部标记为加密 (GPBF bit 0 = 1) 但仍能安装/运行的 APKs。
- 标记核心条目上较大/未知的 Extra fields（查找像 `JADXBLOCK` 之类的标记）。
- 标记路径冲突 (`X` 和 `X/`)，特别针对 `AndroidManifest.xml`、`resources.arsc`、`classes*.dex`。

---

## 参考

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
