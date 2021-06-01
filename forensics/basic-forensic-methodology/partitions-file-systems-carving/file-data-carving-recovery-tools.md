# File/Data Carving & Recovery Tools

## Carving & Recovery tools

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

The most common tool used in forensics to extract files from images is [**Autopsy**](https://www.autopsy.com/download/). Download it, install it and make it ingest the file to find "hidden" files. Note that Autopsy is built to support disk images and other kind of images, but not simple files.

### Binwalk <a id="binwalk"></a>

**Binwalk** is a tool for searching binary files like images and audio files for embedded files and data.  
It can be installed with `apt` however the [source](https://github.com/ReFirmLabs/binwalk) can be found on github.  
**Useful commands**:

```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```

### Foremost

Another common tool to find hidden files is **foremost**. You can find the configuration file of foremost in `/etc/foremost.conf`. If you just want to search for some specific files uncomment them. If you don't uncomment anything foremost will search for it's default configured file types.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** is another tool that can be use to find and extract **files embedded in a file**. In this case you will need to uncomment from the configuration file \(_/etc/scalpel/scalpel.conf_\) the file types you want it to extract.

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Bulk Extractor

This tool comes inside kali but you can find it here: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

This tool can scan an image and will **extract pcaps** inside it, **network information\(URLs, domains, IPs, MACs, mails\)** and more **files**. You only have to do:

```text
bulk_extractor memory.img -o out_folder
```

Navigate through **all the information** that the tool has gathered \(passwords?\), **analyse** the **packets** \(read[ **Pcaps analysis**](../pcap-inspection/)\), search for **weird domains** \(domains related to **malware** or **non-existent**\).

### PhotoRec

You can find it in [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

It comes with GUI and CLI version. You can select the **file-types** you want PhotoRec to search for.

![](../../../.gitbook/assets/image%20%28524%29.png)

## Specific Data Carving Tools

### FindAES

Searches for AES keys by searching for their key schedules. Able to find 128. 192, and 256 bit keys, such as those used by TrueCrypt and BitLocker.

Download [here](https://sourceforge.net/projects/findaes/).

## Complementary tools 

You can use [**viu** ](https://github.com/atanunq/viu)to see images form the terminal.  
You can use the linux command line tool **pdftotext** to transform a pdf into text and read it.

