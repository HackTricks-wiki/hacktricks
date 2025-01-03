# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**命令行工具** 用于管理 **zip 文件** 对于诊断、修复和破解 zip 文件至关重要。以下是一些关键工具：

- **`unzip`**: 揭示 zip 文件无法解压的原因。
- **`zipdetails -v`**: 提供 zip 文件格式字段的详细分析。
- **`zipinfo`**: 列出 zip 文件的内容而不提取它们。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**: 尝试修复损坏的 zip 文件。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: 一种用于暴力破解 zip 密码的工具，适用于大约 7 个字符的密码。

[Zip 文件格式规范](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) 提供了关于 zip 文件结构和标准的全面细节。

需要注意的是，受密码保护的 zip 文件 **不加密文件名或文件大小**，这是一个与 RAR 或 7z 文件不同的安全缺陷，后者会加密这些信息。此外，使用较旧的 ZipCrypto 方法加密的 zip 文件在有未加密的压缩文件副本可用时容易受到 **明文攻击**。此攻击利用已知内容来破解 zip 的密码，这一漏洞在 [HackThis 的文章](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) 中有详细说明，并在 [这篇学术论文](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) 中进一步解释。然而，使用 **AES-256** 加密的 zip 文件对这种明文攻击免疫，展示了为敏感数据选择安全加密方法的重要性。

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{{#include ../../../banners/hacktricks-training.md}}
