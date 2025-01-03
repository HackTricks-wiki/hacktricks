# Adquisición de Imágenes & Montaje

{{#include ../../banners/hacktricks-training.md}}


## Adquisición

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

Puedes [**descargar el FTK imager desde aquí**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

Puedes generar una imagen de disco usando las [**ewf tools**](https://github.com/libyal/libewf).
```bash
ewfacquire /dev/sdb
#Name: evidence
#Case number: 1
#Description: A description for the case
#Evidence number: 1
#Examiner Name: Your name
#Media type: fixed
#Media characteristics: physical
#File format: encase6
#Compression method: deflate
#Compression level: fast

#Then use default values
#It will generate the disk image in the current directory
```
## Montar

### Varios tipos

En **Windows** puedes intentar usar la versión gratuita de Arsenal Image Mounter ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)) para **montar la imagen forense**.

### Raw
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF
```bash
#Get file type
file evidence.E01
evidence.E01: EWF/Expert Witness/EnCase image file format

#Transform to raw
mkdir output
ewfmount evidence.E01 output/
file output/ewf1
output/ewf1: Linux rev 1.0 ext4 filesystem data, UUID=05acca66-d042-4ab2-9e9c-be813be09b24 (needs journal recovery) (extents) (64bit) (large files) (huge files)

#Mount
mount output/ewf1 -o ro,norecovery /mnt
```
### ArsenalImageMounter

Es una aplicación de Windows para montar volúmenes. Puedes descargarla aquí [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Errores

- **`cannot mount /dev/loop0 read-only`** en este caso necesitas usar las flags **`-o ro,norecovery`**
- **`wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.`** en este caso el montaje falló debido a que el desplazamiento del sistema de archivos es diferente al de la imagen del disco. Necesitas encontrar el tamaño del sector y el sector de inicio:
```bash
fdisk -l disk.img
Disk disk.img: 102 MiB, 106954648 bytes, 208896 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00495395

Device        Boot Start    End Sectors  Size Id Type
disk.img1       2048 208895  206848  101M  1 FAT12
```
Tenga en cuenta que el tamaño del sector es **512** y el inicio es **2048**. Luego monte la imagen de esta manera:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
{{#include ../../banners/hacktricks-training.md}}
