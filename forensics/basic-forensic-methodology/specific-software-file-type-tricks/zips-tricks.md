# ZIPs tricks

There are a handful of command-line tools for zip files that will be useful to know about.

* `unzip` will often output helpful information on why a zip will not decompress.
* `zipdetails -v` will provide in-depth information on the values present in the various fields of the format.
* `zipinfo` lists information about the zip file's contents, without extracting it.
* `zip -F input.zip --out output.zip` and `zip -FF input.zip --out output.zip` attempt to repair a corrupted zip file.
* [fcrackzip](https://github.com/hyc/fcrackzip) brute-force guesses a zip password \(for passwords &lt;7 characters or so\).

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

One important security-related note about password-protected zip files is that they do not encrypt the filenames and original file sizes of the compressed files they contain, unlike password-protected RAR or 7z files.

Another note about zip cracking is that if you have an unencrypted/uncompressed copy of any one of the files that is compressed in the encrypted zip, you can perform a "plaintext attack" and crack the zip, as [detailed here](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files), and explained in [this paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). The newer scheme for password-protecting zip files \(with AES-256, rather than "ZipCrypto"\) does not have this weakness.

From: [https://app.gitbook.com/@cpol/s/hacktricks/~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/@cpol/s/hacktricks/~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks)

