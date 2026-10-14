# Forenzika Android uređaja

{{#include ../../banners/hacktricks-training.md}}

## Zaključan uređaj

Dajte prednost metodama prikupljanja podataka koje čuvaju stanje uređaja i zabeležite svaku radnju. Ako je uređaj zaključan, dostupne opcije zavise od modela, verzije Androida, nivoa zakrpe i toga da li je pristup podešen pre zaplene. NIST preporučuje odabir metode u skladu sa uređajem i ovlašćenjem za ispitivanje.<sup>[[1]](#references)</sup>

- Proverite da li je USB debugging bio omogućen i da li je radna stanica za prikupljanje podataka već odobrena. ADB pristup obično zahteva da korisnik otključa uređaj i potvrdi RSA ključ radne stanice.<sup>[[3]](#references)</sup>
- Razmotrite da li je biometrijski pristup i dalje dostupan u skladu sa primenljivim pravnim i proceduralnim pravilima.
- **Smudge attack** može otkriti grafički obrazac za otključavanje na osnovu tragova na ekranu, mada kasniji dodiri i čišćenje smanjuju pouzdanost ove metode.<sup>[[2]](#references)</sup>
- Ako ovlašćeni alati podržavaju konkretan uređaj i verziju softvera, mogu pokušati da oporave ili brute force-om otkriju PIN, lozinku ili obrazac. Provera akreditiva zaštićena hardverom, odlaganje ponovnih pokušaja i pravila brisanja podataka zavise od konkretnog uređaja, zato nemojte koristiti iPhone tehniku ili rezultat kao dokaz da je Android uređaj podržan.<sup>[[1]](#references)</sup>

## Prikupljanje podataka

Na starijim uređajima, zastarela opcija [ADB backup](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) može da napravi `.backup` datoteku koju Android Backup Extractor može da raspakuje:<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

Nemojte pretpostavljati da su ovim obuhvaćene sve aplikacije. ADB označava ovu komandu kao zastarelu, a Android 12 izuzima podatke aplikacija koje ciljaju API level 31 ili noviji, osim ako je aplikacija debuggable.<sup>[[4]](#references)</sup>

### Root ili fizički debug pristup

Uz root pristup aktivnom uređaju, prvo popišite particije i montirane sisteme datoteka; komande u nastavku ne mogu se direktno primeniti na fizičko JTAG preuzimanje podataka. Odgovarajući blok-uređaj zavisi od hardvera, zato nemojte pretpostavljati da je uvek `mmcblk0`. Napravite image samo sa proverenog izvora i sačuvajte ga na zasebnom medijumu:<sup>[[1]](#references)</sup>

JTAG preuzimanje podataka umesto toga koristi hardverski interfejs za testni pristup uređaju i kompatibilnu opremu za preuzimanje, kako bi se pročitala dostupna memorija. Raspored pinova, podrška za čipset, stanje uređaja i razlika između volatilnih i nevolatilnih ciljeva zavise od konkretnog uređaja; dokumentujte putanju pristupa hardveru i primenite validiranu proceduru za taj model.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

Na primer, ako inventar particija potvrđuje da je `/dev/block/mmcblk0` ceo flash uređaj i da odredište ima dovoljno prostora, originalna naredba za pribavljanje postaje:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

Ovde `df /data` pomaže da se `/data` poveže sa montiranim sistemom datoteka; ne treba ga smatrati dokazom da je `mmcblk0` ispravan izvor celog uređaja niti da je `4096` jedina ispravna veličina bloka za `dd`.

Izračunajte heš rezultata i zabeležite tačnu komandu, identifikatore uređaja, vreme i sve promene napravljene tokom prikupljanja podataka.<sup>[[1]](#references)</sup>

### Memorija

LiME može da prikupi fizičku memoriju sa Linux i nekih Android uređaja, ali njegov modul kernela mora biti napravljen za ciljni kernel i učitan uz dovoljne privilegije. Potpisivanje modula, zaključavanje kernela i savremene mere zaštite Androida mogu da spreče njegovo učitavanje.<sup>[[5]](#references)</sup>

Android postupak u projektu prenosi odgovarajući modul pomoću ADB-a, prosleđuje TCP port, učitava modul iz root shell-a i prikuplja tok podataka na hostu za analizu:<sup>[[5]](#references)</sup>

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

LiME može umesto toga da upisuje u prostor za skladištenje na uređaju pomoću `path=/sdcard/ram.lime`, ali to menja skladište uređaja i zahteva dovoljno slobodnog prostora. Zabeležite tu nuspojavu i izračunajte hash pribavljene slike.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Smernice za forenziku mobilnih uređaja](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smudge napadi na ekrane osetljive na dodir pametnih telefona](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Ograničenje ADB backup-a u Androidu 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
