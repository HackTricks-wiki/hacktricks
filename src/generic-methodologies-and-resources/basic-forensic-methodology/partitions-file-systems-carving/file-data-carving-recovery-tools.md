# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

The most common tool used in forensics to extract files from images is [**Autopsy**](https://www.autopsy.com/download/). Download it, install it and make it ingest the file to find "hidden" files. Note that Autopsy is built to support disk images and other kinds of images, but not simple files.

> **2024-2025 update** – Version **4.21** (released February 2025) added a rebuilt **carving module based on SleuthKit v4.13** that is noticeably quicker when dealing with multi-terabyte images and supports parallel extraction on multi-core systems.¹  A small CLI wrapper (`autopsycli ingest <case> <image>`) was also introduced, making it possible to script carving inside CI/CD or large-scale lab environments.

```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** is a tool for analyzing binary files to find embedded content. It's installable via `apt` and its source is on [GitHub](https://github.com/ReFirmLabs/binwalk).

**Useful commands**:

```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```

⚠️  **Security note** – Versions **≤2.3.3** are affected by a **Path Traversal** vulnerability (CVE-2022-4510). Upgrade (or isolate with a container/non-privileged UID) before carving untrusted samples.

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

```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
 git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
 mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```

Useful post-processing scripts (`bulk_diff`, `bulk_extractor_reader.py`) can de-duplicate artefacts between two images or convert results to JSON for SIEM ingestion.

### PhotoRec

You can find it in <https://www.cgsecurity.org/wiki/TestDisk_Download>

It comes with GUI and CLI versions. You can select the **file-types** you want PhotoRec to search for.

![](<../../../images/image (242).png>)

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

Version **1.28** (December 2024) introduced **`--cluster-size`** which can speed up imaging of high-capacity SSDs where traditional sector sizes no longer align with flash blocks.

### Extundelete / Ext4magic (EXT 3/4 undelete)

If the source file system is Linux EXT-based you may be able to recover recently deleted files **without full carving**. Both tools work directly on a read-only image:

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```

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

[YARA-X](https://github.com/VirusTotal/yara-x) is a Rust rewrite of YARA released in 2024.  It is **10-30× faster** than classic YARA and can be used to classify thousands of carved objects very quickly:

```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```

The speed‐up makes it realistic to **auto-tag** all carved files in large-scale investigations.

## Complementary tools

You can use [**viu** ](https://github.com/atanunq/viu)to see images from the terminal.  \
You can use the linux command line tool **pdftotext** to transform a pdf into text and read it.



## References

1. Autopsy 4.21 release notes – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
