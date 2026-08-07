# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple-ov vlasnički sistem datoteka (APFS)

**Apple File System (APFS)** je moderan sistem datoteka dizajniran da zameni Hierarchical File System Plus (HFS+). Njegov razvoj bio je podstaknut potrebom za **boljim performansama, bezbednošću i efikasnošću**.

Neke značajne funkcije APFS-a obuhvataju:<sup>[[1]](#references)</sup>

1. **Deljenje prostora**: APFS omogućava da više volumena **deli isto osnovno slobodno skladište** na jednom fizičkom uređaju. To omogućava efikasnije korišćenje prostora, jer volumeni mogu dinamički da se uvećavaju i smanjuju bez potrebe za ručnim menjanjem veličine ili ponovnim particionisanjem.
1. To znači da, u poređenju sa tradicionalnim particijama na diskovima sa sistemom datoteka, **u APFS-u različite particije (volumeni) dele sav prostor na disku**, dok je obična particija obično imala fiksnu veličinu.
2. **Snapshots**: APFS podržava **kreiranje snapshots**, koji su **samo za čitanje** i predstavljaju stanje sistema datoteka u određenom trenutku. Snapshots omogućavaju efikasne rezervne kopije i jednostavno vraćanje sistema na prethodno stanje, jer zauzimaju minimalan dodatni prostor i mogu se brzo kreirati ili vratiti.
3. **Klonovi**: APFS može da **kreira klonove datoteka ili direktorijuma koji dele isto skladište** kao original sve dok se klon ili originalna datoteka ne izmeni. Ova funkcija omogućava efikasan način za kreiranje kopija datoteka ili direktorijuma bez dupliciranja prostora za skladištenje.
4. **Enkripcija**: APFS **nativno podržava enkripciju celog diska**, kao i enkripciju pojedinačnih datoteka i direktorijuma, čime se poboljšava bezbednost podataka u različitim scenarijima.
5. **Zaštita od padova sistema**: APFS koristi **metadata copy-on-write šemu koja obezbeđuje konzistentnost sistema datoteka** čak i u slučaju iznenadnog nestanka struje ili pada sistema, čime se smanjuje rizik od oštećenja podataka.

Sve u svemu, APFS predstavlja moderniji, fleksibilniji i efikasniji sistem datoteka za Apple uređaje, sa fokusom na bolje performanse, pouzdanost i bezbednost.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` volume je montiran na **`/System/Volumes/Data`** (ovo možete proveriti pomoću `diskutil apfs list`).

Lista firmlinks se nalazi u datoteci **`/usr/share/firmlinks`**.
```bash

```
## Reference

- [1] [APFS vodič - Funkcije - Apple dokumentacija za programere](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
