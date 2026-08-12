# Forensics Androida

{{#include ../banners/hacktricks-training.md}}

## Zablokowane urządzenie

Preferuj metody pozyskiwania danych, które zachowują stan urządzenia, i dokumentuj każde działanie. Jeśli urządzenie jest zablokowane, dostępne opcje zależą od modelu, wersji Androida, poziomu poprawek oraz tego, czy dostęp został skonfigurowany przed przejęciem urządzenia. NIST zaleca wybór metody odpowiednio do urządzenia i uprawnień do przeprowadzenia badania.<sup>[[1]](#references)</sup>

- Sprawdź, czy USB debugging było włączone oraz czy stacja robocza używana do pozyskiwania danych jest już autoryzowana. Dostęp ADB zwykle wymaga od użytkownika odblokowania urządzenia i potwierdzenia klucza RSA stacji roboczej.<sup>[[3]](#references)</sup>
- Rozważ, czy dostęp biometryczny pozostaje dostępny zgodnie z obowiązującymi zasadami prawnymi i proceduralnymi.
- **smudge attack** może ujawnić graficzny wzór odblokowania na podstawie śladów na ekranie, chociaż późniejsze dotknięcia i czyszczenie zmniejszają jego wiarygodność.<sup>[[2]](#references)</sup>
- Jeśli autoryzowane narzędzie obsługuje dokładne urządzenie i kompilację oprogramowania, może podjąć próbę odzyskania lub brute force kodu PIN, hasła albo wzoru. Weryfikacja poświadczeń wspierana sprzętowo, opóźnienia między próbami i zasady czyszczenia danych sprawiają, że jest to wysoce zależne od urządzenia, dlatego nie należy zastępować dowodu obsługi urządzenia Android techniką ani wynikiem dotyczącym iPhone'a.<sup>[[1]](#references)</sup>

## Pozyskiwanie danych

Na starszych urządzeniach starsza wersja [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) może utworzyć plik `.backup`, który Android Backup Extractor potrafi rozpakować:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Nie zakładaj, że obejmuje to każdą aplikację. ADB oznacza tę komendę jako przestarzałą, a Android 12 wyklucza dane aplikacji kierowanych na API level 31 lub nowszy, chyba że aplikacja jest debuggable.<sup>[[4]](#references)</sup>

### Root or physical debug access

Przy dostępie root do działającego urządzenia najpierw zinwentaryzuj partycje i mounty; poniższe komendy nie mają bezpośredniego zastosowania do fizycznego pozyskiwania danych JTAG. Właściwe urządzenie blokowe zależy od sprzętu, więc nie zakładaj, że zawsze jest to `mmcblk0`. Twórz obraz wyłącznie ze zweryfikowanego źródła i zapisuj go na oddzielnym nośniku:<sup>[[1]](#references)</sup>

Pozyskiwanie danych JTAG wykorzystuje interfejs sprzętowy test access urządzenia oraz kompatybilny sprzęt do pozyskiwania danych w celu odczytu dostępnej pamięci. Pinout, obsługa chipsetu, stan urządzenia oraz rozróżnienie między celami volatile i non-volatile zależą od konkretnego urządzenia; udokumentuj ścieżkę sprzętową i zastosuj zwalidowaną procedurę dla danego modelu.<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Na przykład, jeśli inwentaryzacja partycji potwierdza, że `/dev/block/mmcblk0` jest całym urządzeniem flash, a miejsce docelowe ma wystarczającą ilość wolnego miejsca, oryginalne polecenie pozyskiwania danych przyjmuje postać:<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
Tutaj `df /data` pomaga powiązać `/data` z zamontowanym systemem plików; nie należy traktować tego jako dowodu, że `mmcblk0` jest prawidłowym źródłem obejmującym całe urządzenie ani że `4096` jest jedynym poprawnym rozmiarem bloku `dd`.

Oblicz hash wyniku i zapisz dokładne polecenie, identyfikatory urządzenia, czas oraz wszelkie zmiany wprowadzone podczas pozyskiwania danych.<sup>[[1]](#references)</sup>

### Pamięć

LiME może pozyskiwać pamięć fizyczną z systemu Linux i niektórych urządzeń Android, ale jego moduł jądra musi być zbudowany dla docelowego jądra i załadowany z wystarczającymi uprawnieniami. Podpisywanie modułów, kernel lockdown oraz współczesne mechanizmy hardeningu Androida mogą uniemożliwić jego załadowanie.<sup>[[5]](#references)</sup>

Workflow projektu dla Androida przesyła pasujący moduł za pomocą ADB, przekierowuje port TCP, ładuje moduł z root shell i przechwytuje strumień na hoście badawczym:<sup>[[5]](#references)</sup>
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
LiME może zamiast tego zapisywać dane w pamięci urządzenia za pomocą `path=/sdcard/ram.lime`, ale zmienia to pamięć urządzenia i wymaga wystarczającej ilości wolnego miejsca. Odnotuj ten efekt uboczny i oblicz hash pozyskanego obrazu.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Wytyczne dotyczące informatyki śledczej urządzeń mobilnych](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Ataki Smudge na ekrany dotykowe smartfonów](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Ograniczenie kopii zapasowych ADB w Androidzie 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
