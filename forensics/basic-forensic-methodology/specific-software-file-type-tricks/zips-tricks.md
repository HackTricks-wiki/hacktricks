# ZIPs tricks

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

There are a handful of command-line tools for zip files that will be useful to know about.

* `unzip` will often output helpful information on why a zip will not decompress.
* `zipdetails -v` will provide in-depth information on the values present in the various fields of the format.
* `zipinfo` lists information about the zip file's contents, without extracting it.
* `zip -F input.zip --out output.zip` and `zip -FF input.zip --out output.zip` attempt to repair a corrupted zip file.
* [fcrackzip](https://github.com/hyc/fcrackzip) brute-force guesses a zip password (for passwords <7 characters or so).

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

One important security-related note about password-protected zip files is that they do not encrypt the filenames and original file sizes of the compressed files they contain, unlike password-protected RAR or 7z files.

Another note about zip cracking is that if you have an unencrypted/uncompressed copy of any one of the files that are compressed in the encrypted zip, you can perform a "plaintext attack" and crack the zip, as [detailed here](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files), and explained in [this paper](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). The newer scheme for password-protecting zip files (with AES-256, rather than "ZipCrypto") does not have this weakness.

From: [https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/o/Iwnw24TnSs9D9I2OtTKX/s/-L\_2uGJGU7AVNRcqRvEi/)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
