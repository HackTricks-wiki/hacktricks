# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Alati za carving i oporavak

Više alata na [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najčešće korišćen alat u forenzici za ekstrakciju fajlova iz slika je [**Autopsy**](https://www.autopsy.com/download/). Preuzmite ga, instalirajte i omogućite mu da unese fajl kako bi pronašao "sakrivene" fajlove. Imajte na umu da je Autopsy napravljen da podržava disk slike i druge vrste slika, ali ne i obične fajlove.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** je alat za analizu binarnih fajlova radi pronalaženja ugrađenog sadržaja. Može se instalirati putem `apt`, a njegov izvor je na [GitHub](https://github.com/ReFirmLabs/binwalk).

**Korisne komande**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Još jedan uobičajen alat za pronalaženje skrivenih fajlova je **foremost**. Možete pronaći konfiguracioni fajl foremost-a u `/etc/foremost.conf`. Ako želite da pretražujete samo neke specifične fajlove, otkomentarišite ih. Ako ne otkomentarišete ništa, foremost će pretraživati svoje podrazumevane konfiguracione tipove fajlova.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** je još jedan alat koji se može koristiti za pronalaženje i ekstrakciju **datoteka ugrađenih u datoteku**. U ovom slučaju, potrebno je da odkomentarišete tipove datoteka iz konfiguracione datoteke (_/etc/scalpel/scalpel.conf_) koje želite da ekstraktujete.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Ovaj alat dolazi unutar kali, ali ga možete pronaći ovde: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Ovaj alat može skenirati sliku i **izvući pcaps** unutar nje, **mrežne informacije (URL-ovi, domene, IP adrese, MAC adrese, e-mailovi)** i još **datoteka**. Samo treba da uradite:
```
bulk_extractor memory.img -o out_folder
```
Navigirajte kroz **sve informacije** koje je alat prikupio (lozinke?), **analizirajte** **pakete** (pročitajte [**analizu Pcaps**](../pcap-inspection/)), pretražujte **čudne domene** (domene povezane sa **malverom** ili **nepostojećim**).

### PhotoRec

Možete ga pronaći na [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Dolazi sa GUI i CLI verzijama. Možete odabrati **tipove fajlova** koje želite da PhotoRec pretražuje.

![](<../../../images/image (524).png>)

### binvis

Proverite [kod](https://code.google.com/archive/p/binvis/) i [web stranicu alata](https://binvis.io/#/).

#### Karakteristike BinVis

- Vizuelni i aktivni **pregledač strukture**
- Više grafika za različite tačke fokusa
- Fokusiranje na delove uzorka
- **Prikazivanje stringova i resursa**, u PE ili ELF izvršnim datotekama npr.
- Dobijanje **šablona** za kriptoanalizu na fajlovima
- **Prepoznavanje** pakera ili enkodera
- **Identifikacija** steganografije po šablonima
- **Vizuelno** binarno upoređivanje

BinVis je odlična **polazna tačka za upoznavanje sa nepoznatim ciljem** u scenariju crne kutije.

## Specifični alati za vađenje podataka

### FindAES

Pretražuje AES ključeve tražeći njihove rasporede ključeva. Sposoban je da pronađe 128, 192 i 256 bitne ključeve, kao što su oni koje koriste TrueCrypt i BitLocker.

Preuzmite [ovde](https://sourceforge.net/projects/findaes/).

## Komplementarni alati

Možete koristiti [**viu**](https://github.com/atanunq/viu) da vidite slike iz terminala.\
Možete koristiti linux komandnu liniju alat **pdftotext** da transformišete pdf u tekst i pročitate ga.

{{#include ../../../banners/hacktricks-training.md}}
