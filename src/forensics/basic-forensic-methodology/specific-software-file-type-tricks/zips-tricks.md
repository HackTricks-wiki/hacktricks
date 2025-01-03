# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** for managing **zip files** are essential for diagnosing, repairing, and cracking zip files. Here are some key utilities:

- **`unzip`**: Reveals why a zip file may not decompress.
- **`zipdetails -v`**: Offers detailed analysis of zip file format fields.
- **`zipinfo`**: Lists contents of a zip file without extracting them.
- **`zip -F input.zip --out output.zip`** and **`zip -FF input.zip --out output.zip`**: Try to repair corrupted zip files.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: A tool for brute-force cracking of zip passwords, effective for passwords up to around 7 characters.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

It's crucial to note that password-protected zip files **do not encrypt filenames or file sizes** within, a security flaw not shared with RAR or 7z files which encrypt this information. Furthermore, zip files encrypted with the older ZipCrypto method are vulnerable to a **plaintext attack** if an unencrypted copy of a compressed file is available. This attack leverages the known content to crack the zip's password, a vulnerability detailed in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) and further explained in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). However, zip files secured with **AES-256** encryption are immune to this plaintext attack, showcasing the importance of choosing secure encryption methods for sensitive data.

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{{#include ../../../banners/hacktricks-training.md}}



