# Forensics Android

{{#include ../banners/hacktricks-training.md}}

## Zablokowane urządzenie

Preferuj metody pozyskiwania danych, które zachowują stan urządzenia, i dokumentuj każde działanie. Jeśli urządzenie jest zablokowane, dostępne opcje zależą od modelu, wersji Androida, poziomu poprawek oraz tego, czy dostęp został skonfigurowany przed zabezpieczeniem urządzenia. NIST zaleca wybór metody odpowiedniej dla urządzenia i zakresu uprawnień do przeprowadzenia badania.<sup>[[1]](#references)</sup>

- Sprawdź, czy USB debugging był włączony oraz czy stacja robocza używana do pozyskiwania danych została już autoryzowana. Dostęp ADB zwykle wymaga od użytkownika odblokowania urządzenia i potwierdzenia klucza RSA stacji roboczej.<sup>[[3]](#references)</sup>
- Rozważ, czy dostęp biometryczny pozostaje dostępny zgodnie z obowiązującymi przepisami prawnymi i procedurami.
- **smudge attack** może ujawnić graficzny wzór odblokowania na podstawie pozostałości na ekranie, chociaż późniejsze dotknięcia i czyszczenie zmniejszają jego wiarygodność.<sup>[[2]](#references)</sup>
- Korzystaj z komercyjnych lub badawczych narzędzi do omijania blokady tylko wtedy, gdy jawnie obsługują dokładne urządzenie i wersję oprogramowania.

## Pozyskiwanie danych

Na starszych urządzeniach starsza wersja [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) może utworzyć plik `.backup`, który można rozpakować za pomocą Android Backup Extractor:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Nie zakładaj, że obejmuje to każdą aplikację. ADB oznacza to polecenie jako przestarzałe, a Android 12 wyklucza dane aplikacji ukierunkowanych na API level 31 lub nowszy, chyba że aplikacja jest debuggable.<sup>[[4]](#references)</sup>

### Root lub fizyczny dostęp debugowania

Mając dostęp root do działającego urządzenia, najpierw zinwentaryzuj partycje i punkty montowania; poniższe polecenia nie mają bezpośredniego zastosowania do fizycznej akwizycji JTAG. Właściwe urządzenie blokowe zależy od sprzętu, więc nie zakładaj, że zawsze jest to `mmcblk0`. Obraz twórz wyłącznie ze zweryfikowanego źródła i zapisuj go na oddzielnym nośniku:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Zahaszuj wynik i zapisz dokładne polecenie, identyfikatory urządzenia, czas oraz wszelkie zmiany wprowadzone podczas akwizycji.<sup>[[1]](#references)</sup>

### Pamięć

LiME może pozyskiwać zawartość pamięci fizycznej z systemu Linux i niektórych urządzeń Android, ale jego moduł jądra musi być zbudowany dla docelowego jądra i załadowany z wystarczającymi uprawnieniami. Podpisywanie modułów, kernel lockdown i nowoczesne mechanizmy hardeningu Androida mogą uniemożliwić jego załadowanie.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Wytyczne dotyczące informatyki śledczej urządzeń mobilnych](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Ataki Smudge na ekrany dotykowe smartfonów](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Ograniczenie kopii zapasowych ADB w Androidzie 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
