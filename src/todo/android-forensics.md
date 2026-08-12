# Forenzika Androida

{{#include ../banners/hacktricks-training.md}}

## Zaključan uređaj

Prednost dajte metodama pribavljanja koje čuvaju stanje uređaja i dokumentujte svaku radnju. Ako je uređaj zaključan, dostupne opcije zavise od modela, verzije Androida, nivoa zakrpa i toga da li je pristup konfigurisan pre zaplene. NIST preporučuje izbor metode u skladu sa uređajem i ovlašćenjem za ispitivanje.<sup>[[1]](#references)</sup>

- Proverite da li je USB debugging bio omogućen i da li je radna stanica za pribavljanje već autorizovana. ADB pristup obično zahteva da korisnik otključa uređaj i potvrdi RSA ključ radne stanice.<sup>[[3]](#references)</sup>
- Razmotrite da li je biometrijski pristup i dalje dostupan u skladu sa važećim pravnim i proceduralnim pravilima.
- **smudge attack** može otkriti grafički obrazac za otključavanje na osnovu ostataka na ekranu, iako kasniji dodiri i čišćenje umanjuju njegovu pouzdanost.<sup>[[2]](#references)</sup>
- Ako ovlašćeni alati podržavaju tačan uređaj i verziju softvera, mogu pokušati oporavak ili brute force PIN-a, lozinke ili obrasca. Provera akreditiva zasnovana na hardveru, kašnjenja između pokušaja i politike brisanja podataka čine ovo veoma specifičnim za uređaj, zato nemojte zameniti iPhone tehniku ili rezultat dokazom da je Android uređaj podržan.<sup>[[1]](#references)</sup>

## Pribavljanje podataka

Na starijim uređajima, nasleđeni [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) može proizvesti `.backup` datoteku koju Android Backup Extractor može raspakovati:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Nemojte pretpostaviti da ovo obuhvata svaku aplikaciju. ADB označava ovu komandu kao zastarelu, a Android 12 izostavlja podatke iz aplikacija koje ciljaju API level 31 ili noviji, osim ako je aplikacija debuggable.<sup>[[4]](#references)</sup>

### Root ili fizički debug pristup

Sa root pristupom na aktivnom uređaju, najpre napravite inventar particija i mount-ova; komande u nastavku ne primenjuju se direktno na fizičku JTAG akviziciju. Odgovarajući blok uređaj zavisi od hardvera, zato nemojte pretpostaviti da je uvek `mmcblk0`. Imidžujte samo verifikovani izvor na odvojeno skladište:<sup>[[1]](#references)</sup>

JTAG akvizicija umesto toga koristi hardverski interfejs uređaja za testni pristup i kompatibilnu opremu za akviziciju radi čitanja dostupne memorije. Raspored pinova, podrška za chipset, stanje uređaja i razlika između volatilnih i nevolatilnih ciljeva specifični su za uređaj; dokumentujte hardverski put i koristite validiranu proceduru za taj model.<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Na primer, ako popis particija potvrdi da je `/dev/block/mmcblk0` ceo flash uređaj i da odredište ima dovoljno prostora, originalna komanda za pribavljanje postaje:<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
Ovde `df /data` pomaže da se `/data` poveže sa njegovim montiranim filesystemom; ne treba ga tretirati kao dokaz da je `mmcblk0` ispravan izvor celog uređaja ili da je `4096` jedina važeća veličina bloka za `dd`.

Heširaj rezultat i zabeleži tačnu komandu, identifikatore uređaja, vreme i sve izmene napravljene tokom akvizicije.<sup>[[1]](#references)</sup>

### Memorija

LiME može da pribavi fizičku memoriju sa Linux i nekih Android uređaja, ali njegov kernel module mora biti izgrađen za ciljni kernel i učitan sa dovoljnim privilegijama. Potpisivanje modula, kernel lockdown i savremene Android mere zaštite mogu sprečiti njegovo učitavanje.<sup>[[5]](#references)</sup>

Android workflow ovog projekta prosleđuje odgovarajući modul pomoću ADB-a, prosleđuje TCP port, učitava modul iz root shell-a i hvata stream na hostu za ispitivanje:<sup>[[5]](#references)</sup>
```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```
LiME umesto toga može da upisuje podatke u skladište uređaja pomoću `path=/sdcard/ram.lime`, ali to menja skladište uređaja i zahteva dovoljno slobodnog prostora. Zabeležite taj sporedni efekat i izračunajte hash pribavljene slike.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Smernice za forenziku mobilnih uređaja](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Napadi Smudge na ekrane osetljive na dodir pametnih telefona](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Ograničenje ADB backup-a u Androidu 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android alat za ekstrakciju rezervnih kopija](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
