# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Zaključan uređaj

Dajte prednost metodama akvizicije koje čuvaju stanje uređaja i dokumentujte svaku radnju. Ako je uređaj zaključan, dostupne opcije zavise od modela, verzije Androida, nivoa zakrpa i toga da li je pristup konfigurisan pre zaplene. NIST preporučuje izbor metode u skladu sa uređajem i ovlašćenjem za ispitivanje.<sup>[[1]](#references)</sup>

- Proverite da li je USB debugging bio omogućen i da li je radna stanica za akviziciju već autorizovana. ADB pristup obično zahteva da korisnik otključa uređaj i potvrdi RSA ključ radne stanice.<sup>[[3]](#references)</sup>
- Razmotrite da li je biometrijski pristup i dalje dostupan u skladu sa primenljivim pravnim i proceduralnim pravilima.
- **Smudge attack** može otkriti grafički obrazac za otključavanje na osnovu ostataka na ekranu, iako kasniji dodiri i čišćenje smanjuju njegovu pouzdanost.<sup>[[2]](#references)</sup>
- Komercijalne ili istraživačke alate za zaobilaženje zaključavanja koristite samo kada izričito podržavaju konkretan uređaj i verziju softvera.

## Prikupljanje podataka

Na starijim uređajima, legacy [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) može generisati `.backup` datoteku koju Android Backup Extractor može raspakovati:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Nemojte pretpostaviti da ovo obuhvata svaku aplikaciju. ADB označava ovu komandu kao deprecated, a Android 12 izuzima podatke iz aplikacija koje ciljaju API level 31 ili noviji, osim ako je aplikacija debuggable.<sup>[[4]](#references)</sup>

### Root ili fizički debug pristup

Uz root pristup na aktivnom uređaju, najpre popišite particije i mount-ove; komande u nastavku ne primenjuju se direktno na fizičku JTAG akviziciju. Ispravan blok uređaj zavisi od hardvera, zato nemojte pretpostaviti da je uvek `mmcblk0`. Imidžujte samo verifikovani izvor na odvojeno skladište:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Heširaj rezultat i zabeleži tačnu komandu, identifikatore uređaja, vreme i sve promene izvršene tokom prikupljanja.<sup>[[1]](#references)</sup>

### Memorija

LiME može da pribavi fizičku memoriju sa Linux i nekih Android uređaja, ali njegov kernel modul mora biti izgrađen za ciljni kernel i učitan sa dovoljnim privilegijama. Potpisivanje modula, kernel lockdown i moderne Android bezbednosne mere mogu sprečiti njegovo učitavanje.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Smernice za forenziku mobilnih uređaja](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smudge napadi na dodirne ekrane pametnih telefona](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Ograničenje ADB backup-a u Androidu 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
