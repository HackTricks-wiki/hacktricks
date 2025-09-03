# ZIPs 技巧

{{#include ../../../banners/hacktricks-training.md}}

**命令行工具** 用于管理 **zip files**，对诊断、修复和破解 zip files 至关重要。下面是一些关键的实用程序：

- **`unzip`**：显示 zip 文件无法解压的原因。
- **`zipdetails -v`**：提供对 zip 文件格式字段的详细分析。
- **`zipinfo`**：在不解压的情况下列出 zip 文件的内容。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的 zip 文件。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：用于对 zip 密码进行暴力破解的工具，对大约 7 个字符以内的密码有效。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) 提供了关于 zip files 结构和标准的全面细节。

需要注意的是，受密码保护的 zip files **不会加密文件名或文件大小**，这是一个安全缺陷，RAR 或 7z 文件可以加密这些信息。进一步地，使用较旧的 ZipCrypto 方法加密的 zip files 如果存在未加密的压缩文件副本，则容易遭受 **plaintext attack**。该攻击利用已知内容来破解 zip 的密码，相关漏洞在 [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) 中有描述，并在 [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) 中有更详细的解释。然而，使用 **AES-256** 加密的 zip files 对该 plaintext attack 免疫，这凸显了为敏感数据选择安全加密方法的重要性。

---

## 在 APKs 中使用篡改的 ZIP 头的反逆向技巧

现代 Android 恶意软件 dropper 会使用畸形的 ZIP 元数据来破坏静态工具（jadx/apktool/unzip），同时保持 APK 在设备上可安装。最常见的技巧有：

- 通过设置 ZIP General Purpose Bit Flag (GPBF) 的位 0 来伪装加密
- 滥用大型/自定义 Extra 字段以混淆解析器
- 通过文件/目录名冲突来隐藏真实工件（例如，在真实的 `classes.dex` 旁边放置一个名为 `classes.dex/` 的目录）

### 1) 伪装加密（设置 GPBF 位 0）但没有真实加密

症状：
- `jadx-gui` 会报错，例如：

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` 会提示输入核心 APK 文件的密码，尽管有效的 APK 不能对 `classes*.dex`, `resources.arsc`, 或 `AndroidManifest.xml` 进行加密：

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
查看本地和中央头部的通用用途位标志 (General Purpose Bit Flag)。一个明显的值是位 0 被设置 (Encryption)，即使对于核心条目也是如此：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
启发式：如果 APK 在设备上安装并运行，但工具显示核心条目“加密”，则 GPBF 被篡改。

修复方法：在 Local File Headers (LFH) 和 Central Directory (CD) 条目中清除 GPBF 的 bit 0。最小 byte-patcher：
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
使用：
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
你现在应该会在核心条目上看到 `General Purpose Flag  0000`，工具将再次解析 APK。

### 2) 大型/自定义 Extra 字段以破坏解析器

攻击者会在 header 中填充超大的 Extra 字段和奇怪的 ID 来触发反编译器错误。在野外样本中你可能会看到嵌入的自定义标记（例如像 `JADXBLOCK` 这样的字符串）。

检查：
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
观察到的示例：未知 ID，如 `0xCAFE`（"Java Executable"）或 `0x414A`（"JA:"）携带大量 payloads。

DFIR 启发式规则：
- 当核心条目的 Extra fields 异常大时发出警报（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）。
- 将这些条目上的未知 Extra IDs 视为可疑。

实用缓解措施：重建归档（例如，重新压缩提取的文件）会移除恶意的 Extra fields。如果工具因假加密而拒绝提取，先如上清除 GPBF bit 0，然后重新打包：
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 文件/目录 名称冲突（隐藏真实痕迹）

一个 ZIP 可以同时包含文件 `X` 和目录 `X/`。某些解压器和反编译器会混淆，可能会用目录条目覆盖或隐藏真实文件。已观察到条目与像 `classes.dex` 这样的核心 APK 名称发生冲突。

初步评估与安全提取:
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
- 标记那些本地头部标记为加密 (GPBF bit 0 = 1) 但仍可安装/运行的 APKs。
- 标记核心条目上大型或未知的 Extra fields（检查类似 `JADXBLOCK` 的标记）。
- 标记路径冲突 (`X` 和 `X/`)，尤其是对 `AndroidManifest.xml`、`resources.arsc`、`classes*.dex`。

---

## 参考

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
