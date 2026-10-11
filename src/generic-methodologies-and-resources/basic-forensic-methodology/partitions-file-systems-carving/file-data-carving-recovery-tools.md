# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Always carve a **verified copy**, not the original device. See [Image Acquisition & Mount](../image-acquisition-and-mount.md) for read-only acquisition and hashing workflows.

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

The most common tool used in forensics to extract files from images is [**Autopsy**](https://www.autopsy.com/download/). Download it, install it and make it ingest the file to find "hidden" files. Note that Autopsy is built to support disk images and other kinds of images, but not simple files.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** is a tool for analyzing binary files to find embedded content. **Binwalk v3** is a Rust rewrite with automatic extraction (`-e`), raw carving of known and unknown objects (`-c`), recursive/Matryoshka scanning (`-M`) and configurable worker threads. The project recommends its Docker build when all external extractors are required; `cargo install binwalk` installs the Rust CLI but not those external dependencies.<sup>[[11]](#references)</sup>

**Useful v3 commands**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

The legacy v2 `--dd='.*'` recipe is **not** the v3 equivalent of `-c`; first check `binwalk --version` when following old CTF/write-up commands.<sup>[[11]](#references)</sup>

⚠️  **Security note** – Versions **2.1.2b through 2.3.3** are affected by a **Path Traversal** vulnerability (CVE-2022-4510); the advisory lists no patched pip version. Avoid extracting untrusted samples with affected releases, or isolate the tool with a container/non-privileged UID.<sup>[[4]](#references)</sup>

### Foremost

Another common tool to find hidden files is **foremost**. You can find the configuration file of foremost in `/etc/foremost.conf`. If you just want to search for some specific files uncomment them. If you don't uncomment anything foremost will search for its default configured file types.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** is another tool that can be used to find and extract **files embedded in a file**. In this case, you will need to uncomment from the configuration file (_/etc/scalpel/scalpel.conf_) the file types you want it to extract.

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Bulk Extractor 2.x   

This tool comes inside kali but you can find it here: <https://github.com/simsong/bulk_extractor>

Bulk Extractor can scan an evidence image and carve **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** and many other objects **in parallel using multiple scanners**.

The v2.1.1 release documents an Autotools build and the `-S jpeg_carve_mode=2` setting for carving all contiguous JPEGs.<sup>[[2]](#references)</sup>

```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```

The bundled `bulk_diff.py` compares two bulk_extractor runs, while `bulk_extractor_reader.py` reads the report and feature files.<sup>[[3]](#references)</sup>

### PhotoRec

You can find it in <https://www.cgsecurity.org/wiki/TestDisk_Download>

It comes with GUI and CLI versions. You can select the **file-types** you want PhotoRec to search for.

![Run every scanner, carve JPEGs aggressively and generate a bodyfile - PhotoRec: It comes with GUI and CLI versions. You can select the file-types you want PhotoRec to search for](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadata-first)

Before raw signature carving, try filesystem-aware recovery when the volume metadata is still parseable. `tsk_recover` exports only unallocated files by default; `-a` selects allocated files and `-e` exports both. For a whole-disk image, pass the partition's **start sector** from `mmls` to `-o` (do not convert it to bytes). If the input is already a partition image, omit `-o`.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

This pass can preserve filesystem-derived names and paths that header/footer carving cannot; run Foremost, Scalpel or PhotoRec afterwards for entries whose metadata is missing or unusable.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (imaging failing drives)

When a physical drive is unstable, it is best practice to **image it first** and only run carving tools against the image.  `ddrescue` (GNU project) focuses on reliably copying bad disks while keeping a log of unreadable sectors.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

The **`--cluster-size`** option controls how many sectors are copied at a time; smaller values can help with slow drives.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

If the source file system is Linux EXT-based you may be able to recover recently deleted files **without full carving**; these journal-based tools work on an unmounted filesystem or a read-only image.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Compatibility note** – ext4magic is abandoned; its project page warns that current filesystems are no longer compatible with it.<sup>[[10]](#references)</sup>

> 🛈 If the file system was mounted after deletion, the data blocks may have already been reused – in that case proper carving (Foremost/Scalpel) is still required.

### binvis

Check the [code](https://code.google.com/archive/p/binvis/) and the [web page tool](https://binvis.io/#/).

#### Features of BinVis

- Visual and active **structure viewer**
- Multiple plots for different focus points
- Focusing on portions of a sample
- **Seeing stings and resources**, in PE or ELF executables e. g.
- Getting **patterns** for cryptanalysis on files
- **Spotting** packer or encoder algorithms
- **Identify** Steganography by patterns
- **Visual** binary-diffing

BinVis is a great **start-point to get familiar with an unknown target** in a black-boxing scenario.

## Specific Data Carving Tools

### FindAES

Searches for AES keys by searching for their key schedules. Able to find 128. 192, and 256 bit keys, such as those used by TrueCrypt and BitLocker.

Download [here](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) is a Rust rewrite of YARA introduced in 2024; VirusTotal reports that some regular-expression and complex-loop rules can run significantly faster.<sup>[[5]](#references)</sup> Its CLI is named `yr`, and the `scan` command supports recursive scans, a thread count, and metadata output.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Complementary tools

You can use [**viu** ](https://github.com/atanunq/viu)to see images from the terminal.  \
You can use the linux command line tool **pdftotext** to transform a pdf into text and read it.





## References

- [1] [Autopsy 4.21 release notes](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python tools README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal in binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA is dead, long live YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI commands](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue manual](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic manual](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic project status](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: tsk_recover manual](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
