# ZIP 技巧

{{#include ../../../banners/hacktricks-training.md}}

用于管理 **zip 文件**的**命令行工具**对于诊断、修复和破解 zip 文件至关重要。以下是一些常用工具：<sup>[[1]](#references)</sup>

- **`unzip`**：揭示 zip 文件无法解压的原因。
- **`zipdetails -v`**：详细分析 zip 文件格式字段。<sup>[[3]](#references)</sup>
- **`zipinfo`**：列出 zip 文件内容，但不提取文件。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的 zip 文件。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：用于对 ZIP 密码进行字典攻击和暴力破解的工具；是否可行取决于密码搜索空间。<sup>[[15]](#references)</sup>

[Zip 文件格式规范](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)全面介绍了 zip 文件的结构和标准。<sup>[[4]](#references)</sup>

传统的受密码保护 ZIP 文件通常会暴露文件名和文件大小，不像 RAR 和 7z 支持的头部加密模式。ZipCrypto 已知明文攻击恢复的是**内部加密密钥**，不一定是原始密码；这些密钥足以解密使用相同密码加密的条目。<sup>[[13]](#references)</sup>该攻击需要知道**加密前**数据流中的字节：对于未压缩的成员，这些字节就是原始文件字节；对于 DEFLATE 成员，则是压缩后的字节，这可能需要重新生成完全相同的压缩结果。<sup>[[13]](#references)[[14]](#references)</sup>实际操作流程请参见[已知明文 ZIP 攻击](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack)。密码分析背景请参见[论文](https://math.ucr.edu/~mike/zipattacks.pdf)和[演示教程](https://www.hackthissite.org/articles/read/793)。<sup>[[11]](#references)[[12]](#references)</sup>此 ZipCrypto 攻击不适用于 AES 加密的 ZIP 条目。<sup>[[13]](#references)</sup>

---

## 利用篡改的 ZIP 头对 APK 进行反逆向

现代 Android 恶意软件投放器会使用格式错误的 ZIP 元数据来干扰静态分析工具（jadx/apktool/unzip），同时确保 APK 仍能在设备上安装。最常见的技巧包括：<sup>[[2]](#references)</sup>

- 通过设置 ZIP 通用用途位标志（GPBF）的第 0 位来伪造加密
- 滥用大型/自定义 Extra 字段混淆解析器
- 文件/目录名称冲突以隐藏真实文件（例如，在真实的 `classes.dex` 旁放置一个名为 `classes.dex/` 的目录）

### 1) 伪造加密（设置 GPBF 第 0 位），但不进行真实加密

症状：
- `jadx-gui` 报错，例如：
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- 即使有效的 APK 中 `classes*.dex`、`resources.arsc` 或 `AndroidManifest.xml` 不能被加密，`unzip` 仍会提示输入核心 APK 文件的密码：
  
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

查看本地头和中央目录头中的 General Purpose Bit Flag。一个明显的标志是 bit 0 已设置（Encryption），即使对于核心条目也是如此：

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

启发式：如果 APK 能在设备上安装并运行，但工具显示核心条目为“加密”状态，则 GPBF 已被篡改。

修复方法：清除 Local File Headers (LFH) 和 Central Directory (CD) 条目中的 GPBF 位 0。最简字节修补器：

<details>
<summary>最简 GPBF 位清除修补器</summary>

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

只有 bit 0 应该改变：例如，`0A09` 变为 `0A08`，而不是 `0000`。这个最小化补丁工具会在原始字节中扫描文件头签名，因此文件数据中的类似签名字节可能导致误匹配；请在副本上操作，并在使用输出前确认生成的条目列表和文件头。<sup>[[4]](#references)</sup>

### 2) 使用大型/自定义 Extra 字段破坏解析器

攻击者会在文件头中塞入超大的 Extra 字段和奇怪的 ID，以触发反编译器故障。在实际案例中，你可能会看到其中嵌入了自定义标记（例如 `JADXBLOCK` 这样的字符串）。

检查：

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

观察到的示例：未知 ID（如 `0xCAFE`（“Java Executable”）或 `0x414A`（“JA:”））携带了大型载荷。<sup>[[2]](#references)</sup>

DFIR 启发式规则：
- 如果核心条目（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）上的 Extra fields 异常大，则发出警报。
- 将这些条目上的未知 Extra ID 视为可疑。

实用的缓解措施：重建归档（例如，重新压缩提取出的文件）会剥除恶意 Extra fields。如果工具因伪造的加密而拒绝提取，请先按上文所述清除 GPBF bit 0，然后重新打包：

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) 文件/目录名称冲突（隐藏真实工件）

ZIP 中可以同时包含文件 `X` 和目录 `X/`。某些解压工具和反编译器会因此混淆，可能用目录条目覆盖或隐藏真实文件。已发现此问题会影响与 `classes.dex` 等 APK 核心文件名冲突的条目。

分类检查与安全解压：

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
- 标记本地文件头声明已加密（GPBF bit 0 = 1），但仍能安装/运行的 APK。
- 标记核心条目中较大或未知的 Extra 字段（查找 `JADXBLOCK` 等标记）。
- 针对 `AndroidManifest.xml`、`resources.arsc`、`classes*.dex`，标记路径冲突（`X` 和 `X/`）。

---

## 其他恶意 ZIP 技巧（2024–2026）

### 拼接的中央目录（多 EOCD 规避）

在 2024 年的一场钓鱼活动中，攻击者发送了一个实际上由**两个 ZIP 文件拼接而成**的单一数据块。每个文件都有自己的 End of Central Directory (EOCD) 记录和中央目录。不同的解压工具会解析不同的目录（7-Zip 读取第一个，而 WinRAR 读取最后一个），使攻击者能够隐藏仅部分工具可见的载荷；只检查一个目录的扫描器可能会漏掉另一个压缩包。<sup>[[5]](#references)[[6]](#references)</sup>

**排查命令**

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

Quoted-overlap ZIP bombs 会构造一个微小的 **kernel**（高度压缩的 DEFLATE 块），并在重叠条目之间重复使用它。Full-overlap 变体会让多个中央目录条目指向同一个本地文件头，而 quoted-overlap 变体则会在 DEFLATE 流中引用本地文件头；已发布的构造无需嵌套归档即可实现超过 28M:1 的压缩比。<sup>[[7]](#references)</sup>

**快速检测（重复的 LFH 偏移）**

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
- 执行一次 dry-run 遍历：`zipdetails -v file.zip | grep -n "Local Header Offset"`，并比较引用的本地文件头偏移量和压缩数据范围；重复偏移量表示存在完全重叠的变体。<sup>[[7]](#references)[[8]](#references)</sup>
- 提取前，使用解析器限制允许的未压缩总大小和条目数；`zipinfo -t file.zip` 会报告总量，但不会强制执行安全限制。<sup>[[8]](#references)</sup>
- 必须提取时，请在设置了 CPU 和磁盘限制的 cgroup/VM 中进行（避免因无界解压而崩溃）。<sup>[[8]](#references)</sup>

---

### Local-header 与 central-directory 解析器混淆

近期的差异解析器研究表明，ZIP 歧义在现代工具链中仍可被利用。核心思路很简单：有些软件信任 **Local File Header (LFH)**，而其他软件信任 **Central Directory (CD)**，因此同一个归档可以向不同工具呈现不同的文件名、路径、注释、偏移量或条目集。<sup>[[9]](#references)</sup>

实际攻击用途：
- 让上传过滤器、AV 预扫描或软件包验证器在 CD 中看到一个无害文件，而解压器却采用不同的 LFH 名称/路径。
- 利用重复名称、仅存在于一种结构中的条目，或含糊的 Unicode 路径元数据（例如 Info-ZIP Unicode Path Extra Field `0x7075`），使不同解析器重建出不同的目录树。
- 将此问题与路径遍历结合，把“无害”的归档视图转化为解压时的写入原语。关于解压侧，请参阅 [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)。

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

并辅以：

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

启发式规则：
- 对安全敏感的摄取流程，拒绝或隔离 LFH/CD 名称不匹配、文件名重复、包含多个 EOCD 记录，或最终 EOCD 后存在尾随字节的归档。<sup>[[9]](#references)[[10]](#references)</sup>
- 如果不同工具对提取出的文件树解析结果不一致，则应将使用了异常 Unicode 路径扩展字段或不一致注释的 ZIP 视为可疑。<sup>[[4]](#references)[[9]](#references)</sup>
- 如果分析比保留原始字节更重要，可在沙箱中提取归档后，使用严格解析器重新打包，并将生成的文件列表与原始元数据进行比较。

这不仅关系到软件包生态系统：同一类歧义也可能将 payload 藏过邮件网关、静态扫描器和自定义摄取流水线；这些系统会先“窥探”ZIP 内容，再由另一个提取器处理归档。<sup>[[9]](#references)</sup>

---





## References

- [1] [CTF 取证实战指南（Mike's Blog，CTF 分类）](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather——第 1 部分——多阶段 dropper（APK ZIP 反逆向）](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails（IO::Compress 脚本）](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP 文件格式规范（PKWARE APPNOTE.TXT）](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [利用 ZIP 归档的灵活结构隐藏恶意软件而不被检测（Perception Point）](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [黑客在新型 ZIP 文件攻击中藏匿恶意软件——串接 ZIP 中央目录](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [更好的 zip bomb（David Fifield，USENIX WOOT 2019）](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [了解 Zip Bomb：重叠/引用重叠内核构造](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [我的 ZIP 不是你的 ZIP：识别并利用 ZIP 解析器之间的语义差异（USENIX Security 2025）](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [防止针对 Python 软件包安装器的 ZIP 解析器混淆攻击](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [已知明文减少情况下的 ZIP 攻击（Michael Stay，AccessData Corporation）](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site：真实场景 Web 任务，第 15 关（已知明文 ZIP 攻击）](https://www.hackthissite.org/articles/read/793)
- [13] [bkcrack 用法](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [bkcrack 已知明文教程](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [fcrackzip 仓库](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
