{{#include ../../../banners/hacktricks-training.md}}

# Alati za carving

## Autopsy

Najčešći alat korišćen u forenzici za ekstrakciju fajlova iz slika je [**Autopsy**](https://www.autopsy.com/download/). Preuzmite ga, instalirajte i omogućite mu da obradi fajl kako bi pronašao "sakrivene" fajlove. Imajte na umu da je Autopsy napravljen da podržava disk slike i druge vrste slika, ali ne i obične fajlove.

## Binwalk <a id="binwalk"></a>

**Binwalk** je alat za pretraživanje binarnih fajlova kao što su slike i audio fajlovi za ugrađene fajlove i podatke. Može se instalirati pomoću `apt`, međutim [izvor](https://github.com/ReFirmLabs/binwalk) se može pronaći na github-u.  
**Korisne komande**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Još jedan uobičajen alat za pronalaženje skrivenih fajlova je **foremost**. Možete pronaći konfiguracioni fajl foremost-a u `/etc/foremost.conf`. Ako želite da pretražujete samo neke specifične fajlove, otkomentarišite ih. Ako ne otkomentarišete ništa, foremost će pretraživati njegove podrazumevane konfiguracione tipove fajlova.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** je još jedan alat koji se može koristiti za pronalaženje i ekstrakciju **datoteka ugrađenih u datoteku**. U ovom slučaju, potrebno je da otkomentarišete tipove datoteka iz konfiguracione datoteke \(_/etc/scalpel/scalpel.conf_\) koje želite da ekstraktujete.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Ovaj alat dolazi unutar kali, ali ga možete pronaći ovde: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Ovaj alat može skenirati sliku i **izvući pcaps** unutar nje, **mrežne informacije (URL-ovi, domene, IP adrese, MAC adrese, e-mailovi)** i još **datoteka**. Samo treba da uradite:
```text
bulk_extractor memory.img -o out_folder
```
Navigirajte kroz **sve informacije** koje je alat prikupio \(lozinke?\), **analizirajte** **pakete** \(pročitajte [ **Pcaps analiza**](../pcap-inspection/index.html)\), pretražujte **čudne domene** \(domene povezane sa **malverom** ili **nepostojećim**\).

## PhotoRec

Možete ga pronaći na [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Dolazi sa GUI i CLI verzijom. Možete odabrati **tipove fajlova** koje želite da PhotoRec pretražuje.

![](../../../images/image%20%28524%29.png)

# Specifični alati za vađenje podataka

## FindAES

Pretražuje AES ključeve pretražujući njihove rasporede ključeva. Sposoban je da pronađe 128, 192 i 256 bitne ključeve, kao što su oni koje koriste TrueCrypt i BitLocker.

Preuzmite [ovde](https://sourceforge.net/projects/findaes/).

# Dodatni alati

Možete koristiti [**viu** ](https://github.com/atanunq/viu) da vidite slike iz terminala. 
Možete koristiti linux komandnu liniju **pdftotext** da transformišete pdf u tekst i pročitate ga.

{{#include ../../../banners/hacktricks-training.md}}
