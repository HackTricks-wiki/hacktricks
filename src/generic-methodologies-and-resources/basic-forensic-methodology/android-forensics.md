# Analiza kryminalistyczna Androida

{{#include ../../banners/hacktricks-training.md}}

## Zablokowane urządzenie

Preferuj metody pozyskiwania danych, które zachowują stan urządzenia, i dokumentuj każde działanie. Jeśli urządzenie jest zablokowane, dostępne opcje zależą od modelu, wersji Androida, poziomu poprawek oraz tego, czy przed zajęciem urządzenia skonfigurowano dostęp. NIST zaleca wybór metody odpowiedniej dla urządzenia i zakresu uprawnień do przeprowadzenia badania.<sup>[[1]](#references)</sup>

- Sprawdź, czy włączono debugowanie USB i czy stacja robocza używana do pozyskiwania danych została już autoryzowana. Dostęp ADB zazwyczaj wymaga odblokowania urządzenia przez użytkownika i potwierdzenia klucza RSA stacji roboczej.<sup>[[3]](#references)</sup>
- Rozważ, czy dostęp biometryczny jest nadal możliwy zgodnie z obowiązującymi przepisami i procedurami.
- **Smudge attack** może ujawnić wzór odblokowania graficznego na podstawie śladów na ekranie, choć późniejsze dotknięcia ekranu i jego czyszczenie zmniejszają wiarygodność tej metody.<sup>[[2]](#references)</sup>
- Jeśli autoryzowane narzędzia obsługują dany model urządzenia i konkretną wersję oprogramowania, mogą podjąć próbę odzyskania lub brute force kodu PIN, hasła albo wzoru. Weryfikacja poświadczeń wspierana sprzętowo, opóźnienia między próbami i zasady usuwania danych sprawiają, że jest to kwestia ściśle zależna od urządzenia, dlatego nie należy traktować techniki ani wyniku dotyczącego iPhone’a jako dowodu obsługi urządzenia z Androidem.<sup>[[1]](#references)</sup>

## Pozyskiwanie danych

Na starszych urządzeniach starsza wersja funkcji [ADB backup](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) może utworzyć plik `.backup`, który Android Backup Extractor potrafi rozpakować:<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

Nie zakładaj, że obejmuje to wszystkie aplikacje. ADB oznacza to polecenie jako przestarzałe, a Android 12 wyklucza dane aplikacji kierowanych na API level 31 lub nowszy, chyba że aplikacja jest debugowalna.<sup>[[4]](#references)</sup>

### Dostęp przez root lub fizyczny dostęp debugowania

Mając dostęp przez root do działającego urządzenia, najpierw zinwentaryzuj partycje i punkty montowania; poniższe polecenia nie mają bezpośredniego zastosowania do fizycznego pozyskiwania danych przez JTAG. Właściwe urządzenie blokowe zależy od sprzętu, więc nie zakładaj, że zawsze jest to `mmcblk0`. Wykonaj obraz wyłącznie zweryfikowanego źródła na oddzielnym nośniku:<sup>[[1]](#references)</sup>

Pozyskiwanie danych przez JTAG wykorzystuje sprzętowy interfejs dostępu testowego urządzenia oraz kompatybilny sprzęt akwizycji do odczytu dostępnej pamięci. Rozkład pinów, obsługa chipsetu, stan urządzenia oraz rozróżnienie między celami ulotnymi i nieulotnymi zależą od urządzenia; udokumentuj ścieżkę sprzętową i zastosuj zweryfikowaną procedurę dla danego modelu.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

Na przykład, jeśli inwentaryzacja partycji potwierdza, że `/dev/block/mmcblk0` jest całym urządzeniem pamięci flash, a w miejscu docelowym jest wystarczająco dużo miejsca, oryginalne polecenie pozyskiwania danych wygląda następująco:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

Tutaj `df /data` pomaga powiązać `/data` z zamontowanym systemem plików; nie należy traktować go jako dowodu, że `mmcblk0` jest właściwym źródłem całego urządzenia ani że `4096` to jedyny prawidłowy rozmiar bloku dla `dd`.

Oblicz hash wyniku i zapisz dokładne polecenie, identyfikatory urządzenia, czas oraz wszelkie zmiany wprowadzone podczas pozyskiwania danych.<sup>[[1]](#references)</sup>

### Pamięć

LiME może pozyskiwać pamięć fizyczną z systemu Linux i niektórych urządzeń z Androidem, ale jego moduł jądra musi być zbudowany dla jądra docelowego i załadowany z odpowiednimi uprawnieniami. Podpisywanie modułów, blokada jądra i współczesne mechanizmy ochrony Androida mogą uniemożliwić jego załadowanie.<sup>[[5]](#references)</sup>

Procedura projektu dla Androida przesyła za pomocą ADB pasujący moduł, przekierowuje port TCP, ładuje moduł z powłoki roota i przechwytuje strumień na hoście analitycznym:<sup>[[5]](#references)</sup>

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

LiME może zamiast tego zapisać dane w pamięci urządzenia, używając `path=/sdcard/ram.lime`, ale zmienia to zawartość pamięci urządzenia i wymaga wystarczającej ilości wolnego miejsca. Zapisz ten skutek uboczny i oblicz skrót pozyskanego obrazu.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Wytyczne dotyczące informatyki śledczej na urządzeniach mobilnych](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Ataki Smudge na ekrany dotykowe smartfonów](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Ograniczenie kopii zapasowej ADB w Androidzie 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
